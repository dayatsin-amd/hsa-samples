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
    if (flag & HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_FINE_GRAINED || flag & HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_COARSE_GRAINED) {
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

    // Initialize
    CHECK_ERROR(hsa_init());

    // Discover devices
    CHECK_ERROR(hsa_iterate_agents(get_devices, &devices));

    // Sanity check
    if (0 == devices.cpu.handle || 0 == devices.gpu.handle) {
        std::cerr << "Device discovery failed, no CPUs or GPUs found exiting." << std::endl;
        return 1;
    }

    uint32_t *device_ptr = NULL;

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

    CHECK_ERROR(hsa_amd_memory_pool_allocate(devices.gpu_pool, max_size, 0,
                                    reinterpret_cast<void**>(&device_ptr)));

    CHECK_ERROR(hsa_amd_agents_allow_access(1, &devices.cpu, NULL, device_ptr));

    printf("Using %ld iterations for each size\n", iterations);

    for (int i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
        for (int j = 0; j < iterations; j++) {
            CHECK_ERROR(hsa_amd_memory_fill(device_ptr, j & 0xFFFF, sizes[i].sz/4));
            for (int k = 0; k < sizes[i].sz/4; k++) {
                if (device_ptr[k] != (j & 0xFFFF)) {
                    printf("Error at %d: %d != %d\n", k, device_ptr[k], (j & 0xFFFF));
                    return 1;
                }
            }
            printf(".");
            fflush(stdout);
        }
        printf("\nSize:%s iteration:%ld passed\n", sizes[i].str, iterations);
        fflush(stdout);
    }
    printf("\nTest completed successfully\n");

    // Shutdown
    CHECK_ERROR(hsa_shut_down());

    // Steady as she goes
    return 0;
}
