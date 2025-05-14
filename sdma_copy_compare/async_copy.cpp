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
#include <chrono>

#define CHECK_ERROR(x) do { if((x) != HSA_STATUS_SUCCESS) { std::cerr << "API failure line #: " <<  __LINE__ << std::endl; abort(); } } while (0)

struct Devices {
    hsa_agent_t cpu, gpu;
    uint32_t gpu_min_queue_size;
     hsa_amd_memory_pool_t cpu_pool;
     hsa_amd_memory_pool_t gpu_pool;
} devices = { };

struct Queue {
    hsa_queue_t* queue;
    uint64_t doorbell_id;
};

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
        CHECK_ERROR(hsa_amd_agent_iterate_memory_pools(agent, get_memory_pool, &devices->cpu_pool));
    } else if (HSA_DEVICE_TYPE_GPU == type && 0 == devices->gpu.handle) {
        devices->gpu = agent;
        CHECK_ERROR(hsa_amd_agent_iterate_memory_pools(agent, get_memory_pool, &devices->gpu_pool));
    }
    return HSA_STATUS_SUCCESS;
}

typedef struct {
    size_t sz;
    const char *str;
} size_info_t;

int main(int argc, char *argv[])
{
    bool use_memcpy = false;
    if (argc >= 2 && !strcmp(argv[1], "-memcpy"))
        use_memcpy = true;

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

    // Create Copy completion signal
    hsa_signal_t signal = { 0 };
    CHECK_ERROR(hsa_signal_create(1, 0, nullptr, &signal));

    void* host_ptr_src = NULL;
    void* device_ptr_dst = NULL;

    size_info_t sizes[] = {
        { 4*1024,           "4K" },
        { 8*1024,           "8K" },
        { 64*1024,          "64K" },
        { 128*1024,         "128K" },
        { 512*1024,         "512K" },
        { 1*1024*1024,      "1MB" },
        { 8*1024*1024,      "8MB" },
        { 32*1024*1024,     "32MB" },
        { 128*1024*1024,    "128MB" },
        { 512*1024*1024,    "512MB" },
        { 2*1024*1024*1024UL,    "2GB" },
    };

    size_t iterations = 100;


    size_t max_size = sizes[(sizeof(sizes)/sizeof(sizes[0]))-1].sz;

    CHECK_ERROR(hsa_amd_memory_pool_allocate(devices.cpu_pool, max_size, 0,
                                reinterpret_cast<void**>(&host_ptr_src)));

    CHECK_ERROR(hsa_amd_memory_pool_allocate(devices.gpu_pool, max_size, 0,
                                    reinterpret_cast<void**>(&device_ptr_dst)));

    //CHECK_ERROR(hsa_amd_agents_allow_access(1, &devices.cpu, NULL, device_ptr_dst));
    CHECK_ERROR(hsa_amd_agents_allow_access(1, &devices.gpu, NULL, host_ptr_src));

    //Dummy copy to create internal queues in ROCr etc..
    CHECK_ERROR(hsa_amd_memory_async_copy(device_ptr_dst, devices.gpu, host_ptr_src, devices.cpu, sizes[0].sz, 0, NULL, signal));
    hsa_signal_wait_acquire(signal, HSA_SIGNAL_CONDITION_LT, 1, -1, HSA_WAIT_STATE_ACTIVE);

    printf("Using %s: %ld iterations for each size\n", use_memcpy ? "memcpy" : "hsa_copy", iterations);

    for (int i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < iterations; j++) {
            if (use_memcpy) {
                memcpy(device_ptr_dst, host_ptr_src, sizes[i].sz);
            } else {
                hsa_signal_store_relaxed(signal, 1);

                CHECK_ERROR(hsa_amd_memory_async_copy(device_ptr_dst, devices.gpu, host_ptr_src, devices.cpu, sizes[i].sz, 0, NULL, signal));
                hsa_signal_wait_acquire(signal, HSA_SIGNAL_CONDITION_LT, 1, -1, HSA_WAIT_STATE_ACTIVE);
            }
        }

        auto elapsed = std::chrono::high_resolution_clock::now() - start;
        long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();

        printf("Size:%s took:%llu us\n", sizes[i].str, microseconds /iterations);
    }

    // Clean up
    CHECK_ERROR(hsa_signal_destroy(signal));

    // Shutdown
    CHECK_ERROR(hsa_shut_down());

    // Steady as she goes
    return 0;
}
