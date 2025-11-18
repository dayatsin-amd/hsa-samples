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

    void *ptr = NULL;
    uint32_t gpu_node_id = 0;
    CHECK_ERROR(hsa_agent_get_info(devices.gpu, HSA_AGENT_INFO_NODE, &gpu_node_id));


    CHECK_ERROR(hsa_amd_vmem_address_reserve(&ptr, 0x10000, 0, HSA_AMD_VMEM_ADDRESS_NO_REGISTER));

    hsa_amd_svm_attribute_pair_t attributes[2] = {};

    attributes[0].attribute = HSA_AMD_SVM_ATTRIB_PREFERRED_LOCATION;
    attributes[0].value = (uint64_t)devices.cpu.handle;
    attributes[1].attribute = HSA_AMD_SVM_ATTRIB_AGENT_ACCESSIBLE; 
    attributes[1].value = (uint64_t)devices.gpu.handle ;
	

    CHECK_ERROR(hsa_amd_svm_attributes_set(ptr, 0x10000, attributes, sizeof(attributes)/sizeof(attributes[0])));

    CHECK_ERROR(hsa_amd_vmem_address_free(ptr, 0x10000));

    // Shutdown
    CHECK_ERROR(hsa_shut_down());

    // Steady as she goes
    return 0;
}
