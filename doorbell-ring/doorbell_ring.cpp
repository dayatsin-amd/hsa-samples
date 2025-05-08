/************************************************************************
 * This code tests whether the xchg instruction works on MMIO memory.
************************************************************************/

#include <iostream>
#include <cstring>
#include <string>
#include <cassert>
#include <atomic>
#include <fcntl.h>
#include "hsa/hsa.h"
#include "hsa/hsa_ext_amd.h"

#define CHECK_ERROR(x) do { if((x) != HSA_STATUS_SUCCESS) { std::cerr << "API failure line #: " <<  __LINE__ << std::endl; abort(); } } while (0)

struct Devices {
    hsa_agent_t cpu, gpu;
    uint32_t gpu_min_queue_size;
} devices = { };

struct Queue {
    hsa_queue_t* queue;
    uint64_t doorbell_id;
};

static constexpr int c11AtomicFlag()
{
  return __ATOMIC_RELAXED;
}

static hsa_status_t get_memory_pool(hsa_amd_memory_pool_t pool, void *data) {
    hsa_amd_segment_t segment;
    CHECK_ERROR(hsa_amd_memory_pool_get_info(pool, HSA_AMD_MEMORY_POOL_INFO_SEGMENT, &segment));
    if (segment != HSA_AMD_SEGMENT_GLOBAL) {
        return HSA_STATUS_SUCCESS;
    }
    hsa_amd_memory_pool_global_flag_t flag;
    CHECK_ERROR(hsa_amd_memory_pool_get_info(pool, HSA_AMD_MEMORY_POOL_INFO_GLOBAL_FLAGS, &flag));
    if (flag & HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_FINE_GRAINED) {
        *(hsa_amd_memory_pool_t*)data = pool;
    }
    return HSA_STATUS_SUCCESS;
}

static hsa_status_t get_devices(hsa_agent_t agent, void *data) {
    hsa_device_type_t type;
    CHECK_ERROR(hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE, &type));
    Devices *devices = (Devices*)data;
    if (HSA_DEVICE_TYPE_CPU == type && 0 == devices->cpu.handle) {
        devices->cpu = agent;
    } else if (HSA_DEVICE_TYPE_GPU == type && 0 == devices->gpu.handle) {
        devices->gpu = agent;
        CHECK_ERROR(hsa_agent_get_info(agent, HSA_AGENT_INFO_QUEUE_MIN_SIZE, &devices->gpu_min_queue_size));
    }
    return HSA_STATUS_SUCCESS;
}

static void submit_packet(Queue* queue, hsa_barrier_or_packet_t& packet) {
    size_t qMask = queue->queue->size - 1;
    hsa_barrier_or_packet_t *qPtr = (hsa_barrier_or_packet_t*) queue->queue->base_address;

    uint64_t wIndex = hsa_queue_load_write_index_relaxed(queue->queue);
    qPtr[wIndex & qMask] = packet;

    hsa_queue_store_write_index_screlease(queue->queue, wIndex + 1);
    __atomic_store((volatile uint64_t*)queue->doorbell_id, &wIndex, c11AtomicFlag());
    //__atomic_store((volatile uint64_t*)queue->doorbell_id, &wIndex, __ATOMIC_RELAXED);
}

int main()
{
    // Initialize
    CHECK_ERROR(hsa_init());

    // Discover devices
    CHECK_ERROR(hsa_iterate_agents(get_devices, &devices));

    // Sanity check
    if (0 == devices.cpu.handle || 0 == devices.gpu.handle) {
        std::cerr << "Device discovery failed, no CPUs or GPUs found exiting." << std::endl;
        return 1;
    }

    // Create AQL queue
    Queue queue = {};
    CHECK_ERROR(hsa_queue_create(devices.gpu, devices.gpu_min_queue_size, HSA_QUEUE_TYPE_MULTI, nullptr, nullptr, 0, 0, &queue.queue));
    CHECK_ERROR(hsa_amd_queue_get_info(queue.queue, HSA_AMD_QUEUE_INFO_DOORBELL_ID, &queue.doorbell_id));

    // Create AQL completion signal
    hsa_signal_t signal = { 0 };
    CHECK_ERROR(hsa_signal_create(1, 0, nullptr, &signal));

    // Initialize AQL Barrier OR
    hsa_barrier_or_packet_t packet = { 0 };
    packet.header |= HSA_PACKET_TYPE_BARRIER_OR << HSA_PACKET_HEADER_TYPE;
    packet.completion_signal = signal;

    std::cout << "Submitting Barrier packet." << std::endl;
    submit_packet(&queue, packet);

    hsa_signal_wait_acquire(signal, HSA_SIGNAL_CONDITION_LT, 1, -1, HSA_WAIT_STATE_ACTIVE);
    std::cout << "Barrier packet processed" << std::endl;

    // Clean up
    CHECK_ERROR(hsa_signal_destroy(signal));
    CHECK_ERROR(hsa_queue_destroy(queue.queue));

    // Shutdown
    CHECK_ERROR(hsa_shut_down());

    // Steady as she goes
    return 0;
}
