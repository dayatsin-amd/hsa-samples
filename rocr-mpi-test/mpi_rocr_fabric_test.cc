


#include <mpi.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <cstdlib>
#include <errno.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <fstream>
#include <fcntl.h>

#include "hsa/hsa_ext_amd.h"
#include "hsa/hsa.h"

enum {
    LOG_ERROR,
    LOG_INFO,
    LOG_DEBUG,
} verbose_level;

/* Global variables */

int gVerboseLevel = LOG_DEBUG;
char gProcessorName[MPI_MAX_PROCESSOR_NAME];
int gRank = -1;
int gPartnerRank = -1;
std::vector<hsa_agent_t> gCpus;
std::vector<hsa_agent_t> gGpus;
hsa_amd_memory_pool_t gDevicePool = {};

//constexpr size_t BUFFER_SIZE = 1024;
constexpr size_t BUFFER_SIZE = 256; /* Alloc size of 4K */
//constexpr size_t BUFFER_SIZE = 64;    /* Alloc size of 1K */

struct test_data_t {
  int src[BUFFER_SIZE];
  int dst[BUFFER_SIZE];
  int write_dst[BUFFER_SIZE];
  int src_copy[BUFFER_SIZE];
};

/* Constants */

/* Helpers */
#define HSA_EXEC(cmd, ret) \
do { \
        hsa_status_t error = (cmd);\
        if (error != HSA_STATUS_SUCCESS) {\
                const char* errorStr;\
                LogPrint(LOG_ERROR, "HSA command returned error:%d %s\n", error, hsa_status_string(error, &errorStr));\
                return ret;\
        }\
} while (0)

void log_printf(const char *file, int line, const char* format, ...) {
    va_list ap;
    va_start(ap, format);
    char message[4096];
    vsnprintf(message, sizeof(message), format, ap);
    va_end(ap);
    printf("[%s|%d] (%s:%d) %s",
          gProcessorName, gRank, file, line, message);

    fflush(stdout);
}

#define LogPrint(verbose, format, ...)                                         \
    do {                                                                       \
        if (verbose <= gVerboseLevel) {                                        \
            log_printf(__FILE__, __LINE__, format, ##__VA_ARGS__);              \
        }                                                                      \
    } while (false);

static char str[96];
//static char str[200];
char *fabric_handle_str(hsa_fabric_handle_t &handle) {
    sprintf(str, "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                handle.handle[0], handle.handle[1], handle.handle[2], handle.handle[3],
                handle.handle[4], handle.handle[5], handle.handle[6], handle.handle[7],
                handle.handle[8], handle.handle[9], handle.handle[10], handle.handle[11],
                handle.handle[12], handle.handle[13], handle.handle[14], handle.handle[15]);
    return str;
}

typedef struct GpuReadWriteKernel {
  uint64_t kernel_object;
  uint32_t group_segment_size;   ///< Kernel group seg size
  uint32_t private_segment_size;   ///< Kernel private seg size
  uint32_t length;
  std::string kernel_file_name;
  std::string kernel_name;
  uint32_t kernarg_size;
  uint32_t kernarg_align;
  hsa_agent_t gpu_dev;
} GpuReadWriteKernel;

void InitializeGpuReadWriteKernel(GpuReadWriteKernel* kern, size_t bufferSize, hsa_agent_t agent) {
  kern->kernel_file_name = "gpuReadWrite_kernels.hsaco";
  kern->kernel_name = "gpuReadWrite.kd";
  kern->length = bufferSize;
  kern->gpu_dev = agent;
}

template <typename T>
static  T AlignDown(T value, size_t alignment) {
  return (T)((value / alignment) * alignment);
}

template <typename T>
static  T AlignUp(T value, size_t alignment) {
  return AlignDown((T)(value + alignment - 1), alignment);
}


hsa_status_t LoadKernelFromObjFile(GpuReadWriteKernel* kern) {
  hsa_status_t err;
  hsa_code_object_reader_t code_obj_rdr = {0};
  hsa_executable_t executable = {0};

  char agent_name[64];
  err = hsa_agent_get_info(kern->gpu_dev, HSA_AGENT_INFO_NAME, agent_name);
  if (err != HSA_STATUS_SUCCESS) return err;

  std::string fileName = std::string("./") + agent_name + "/" + kern->kernel_file_name;

  LogPrint(LOG_INFO, "Opening kernel file:%s\n", fileName.c_str());
  hsa_file_t file_handle = open(fileName.c_str(), O_RDONLY);

  if (file_handle == -1) {
    LogPrint(LOG_ERROR, "Failed to open kernel file (%s)\n", fileName.c_str());
    return HSA_STATUS_ERROR;
  }

  err = hsa_code_object_reader_create_from_file(file_handle, &code_obj_rdr);
  close(file_handle);
  if (err != HSA_STATUS_SUCCESS) return err;

  err = hsa_executable_create_alt(HSA_PROFILE_FULL,
                HSA_DEFAULT_FLOAT_ROUNDING_MODE_DEFAULT, NULL, &executable);
  if (err != HSA_STATUS_SUCCESS) return err;

  err = hsa_executable_load_agent_code_object(executable, kern->gpu_dev,
        code_obj_rdr, NULL, NULL);
  if (err != HSA_STATUS_SUCCESS) return err;

  err = hsa_executable_freeze(executable, NULL);
  if (err != HSA_STATUS_SUCCESS) return err;

  hsa_executable_symbol_t kern_sym;
  err = hsa_executable_get_symbol(executable, NULL, kern->kernel_name.c_str(),
                                  kern->gpu_dev, 0, &kern_sym);
  if (err != HSA_STATUS_SUCCESS) return err;

  err = hsa_executable_symbol_get_info(kern_sym,
                                    HSA_EXECUTABLE_SYMBOL_INFO_KERNEL_OBJECT,
                                                          &kern->kernel_object);
  if (err != HSA_STATUS_SUCCESS) return err;

  err = hsa_executable_symbol_get_info(kern_sym,
                      HSA_EXECUTABLE_SYMBOL_INFO_KERNEL_PRIVATE_SEGMENT_SIZE,
                                                   &kern->private_segment_size);
  if (err != HSA_STATUS_SUCCESS) return err;

  err = hsa_executable_symbol_get_info(kern_sym,
                        HSA_EXECUTABLE_SYMBOL_INFO_KERNEL_GROUP_SEGMENT_SIZE,
                                                     &kern->group_segment_size);
  if (err != HSA_STATUS_SUCCESS) return err;

  // Remaining queries not supported on code object v3.
  err = hsa_executable_symbol_get_info(kern_sym,
                      HSA_EXECUTABLE_SYMBOL_INFO_KERNEL_KERNARG_SEGMENT_SIZE,
                                                           &kern->kernarg_size);
  if (err != HSA_STATUS_SUCCESS) return err;

  err = hsa_executable_symbol_get_info(kern_sym,
                 HSA_EXECUTABLE_SYMBOL_INFO_KERNEL_KERNARG_SEGMENT_ALIGNMENT,
                                                          &kern->kernarg_align);
  if (err != HSA_STATUS_SUCCESS) return err;

  if (kern->kernarg_align < 16) {
    LogPrint(LOG_ERROR, "Kernarg align size is too small\n");
    return HSA_STATUS_ERROR;
  }

  kern->kernarg_align = (kern->kernarg_align == 0) ? 16 : kern->kernarg_align;
  return err;
}

// Find CPU Agents
hsa_status_t IterateCPUAgents(hsa_agent_t agent, void *data) {
  hsa_status_t status;
  if (data == nullptr) {
    return HSA_STATUS_ERROR_INVALID_ARGUMENT;
  }

  std::vector<hsa_agent_t>* cpus = static_cast<std::vector<hsa_agent_t>*>(data);
  hsa_device_type_t device_type;
  status = hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE, &device_type);
  if (HSA_STATUS_SUCCESS == status && HSA_DEVICE_TYPE_CPU == device_type)
    cpus->push_back(agent);
  return status;
}

// Find GPU Agents
hsa_status_t IterateGPUAgents(hsa_agent_t agent, void *data) {
  hsa_status_t status;
  if (data == nullptr) return HSA_STATUS_ERROR_INVALID_ARGUMENT;

  std::vector<hsa_agent_t>* gpus = static_cast<std::vector<hsa_agent_t>*>(data);
  hsa_device_type_t device_type;
  status = hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE, &device_type);
  if (HSA_STATUS_SUCCESS == status && HSA_DEVICE_TYPE_GPU == device_type)
    gpus->push_back(agent);
  return status;
}

hsa_status_t GetGlobalMemoryPool(hsa_amd_memory_pool_t pool, void* data) {
  hsa_amd_segment_t segment;
  hsa_status_t err;
  hsa_amd_memory_pool_t* ret = reinterpret_cast<hsa_amd_memory_pool_t*>(data);

  HSA_EXEC(hsa_amd_memory_pool_get_info(pool,
                                         HSA_AMD_MEMORY_POOL_INFO_SEGMENT,
                                         &segment), HSA_STATUS_ERROR);
  if (HSA_AMD_SEGMENT_GLOBAL != segment)
    return HSA_STATUS_SUCCESS;

  hsa_amd_memory_pool_global_flag_t flags;
  HSA_EXEC(hsa_amd_memory_pool_get_info(pool,
                                        HSA_AMD_MEMORY_POOL_INFO_GLOBAL_FLAGS,
                                        &flags), HSA_STATUS_ERROR);

  if ((flags & HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_COARSE_GRAINED))
    *ret = pool;
  return HSA_STATUS_SUCCESS;
}

hsa_status_t GetKernArgMemoryPool(hsa_amd_memory_pool_t pool, void* data) {
  hsa_status_t err;
  if (nullptr == data) {
    return HSA_STATUS_ERROR_INVALID_ARGUMENT;
  }
  hsa_amd_segment_t segment;
  err = hsa_amd_memory_pool_get_info(pool,
                                         HSA_AMD_MEMORY_POOL_INFO_SEGMENT,
                                         &segment);
  if (HSA_AMD_SEGMENT_GLOBAL != segment) {
    return HSA_STATUS_SUCCESS;
  }

  hsa_amd_memory_pool_global_flag_t flags;
  err = hsa_amd_memory_pool_get_info(pool,
                                         HSA_AMD_MEMORY_POOL_INFO_GLOBAL_FLAGS,
                                         &flags);

  if (flags & HSA_AMD_MEMORY_POOL_GLOBAL_FLAG_KERNARG_INIT) {
    hsa_amd_memory_pool_t* ret =
                                reinterpret_cast<hsa_amd_memory_pool_t*>(data);
    *ret = pool;
  }

  return HSA_STATUS_SUCCESS;
}

void WriteAQLToQueueLoc(hsa_queue_t *queue, uint64_t indx,
                                      hsa_kernel_dispatch_packet_t *aql_pkt) {
  void *queue_base = queue->base_address;
  const uint32_t queue_mask = queue->size - 1;
  hsa_kernel_dispatch_packet_t* queue_aql_packet;

  queue_aql_packet =
       &(reinterpret_cast<hsa_kernel_dispatch_packet_t*>(queue_base))
                                                        [indx & queue_mask];

  queue_aql_packet->workgroup_size_x = aql_pkt->workgroup_size_x;
  queue_aql_packet->workgroup_size_y = aql_pkt->workgroup_size_y;
  queue_aql_packet->workgroup_size_z = aql_pkt->workgroup_size_z;
  queue_aql_packet->grid_size_x = aql_pkt->grid_size_x;
  queue_aql_packet->grid_size_y = aql_pkt->grid_size_y;
  queue_aql_packet->grid_size_z = aql_pkt->grid_size_z;
  queue_aql_packet->private_segment_size =
                                     aql_pkt->private_segment_size;
  queue_aql_packet->group_segment_size =
                                       aql_pkt->group_segment_size;
  queue_aql_packet->kernel_object = aql_pkt->kernel_object;
  queue_aql_packet->kernarg_address = aql_pkt->kernarg_address;
  queue_aql_packet->completion_signal = aql_pkt->completion_signal;
}

inline void AtomicSetPacketHeader(uint16_t header, uint16_t setup,
                                hsa_kernel_dispatch_packet_t* queue_packet) {
  __atomic_store_n(reinterpret_cast<uint32_t*>(queue_packet),
                                    header | (setup <<16), __ATOMIC_RELEASE);
}

int VerifyLocalData(int *src, int *dst, int *write_dst, int *src_copy, size_t size) {
  for (int i = 0; i < size; ++i) {
    // printf("Verifying data at index[%d]\n", i);
    if (dst[i] != src_copy[i]) {
      LogPrint(LOG_DEBUG, "Data verification failed index:%d dst:%x src_copy:%x\n", i, dst[i], src_copy[i]);
      return -1;
    }
  }

  LogPrint(LOG_DEBUG, "GPU copied data to dst successfully\n");

  for (int i = 0; i < size; ++i) {
      if (write_dst[i] != i) {
        LogPrint(LOG_DEBUG, "Data verification failed index:%d write_dst:%x src_copy:%x\n", i, write_dst[i]);
        return -1;
      }
  }
  LogPrint(LOG_DEBUG, "GPU wrote data to write_dst successfully\n");
  return 0;
}

int LaunchAccessDispatch(hsa_agent_t gpuAgent, hsa_agent_t cpuAgent, int *src, int *dst, int *write_dst, int *src_copy, size_t size) {
  hsa_queue_t* queue = NULL;  // command queue
  hsa_signal_t signal = {0};  // completion signal

  GpuReadWriteKernel accessKernel = {};

  typedef struct __attribute__((aligned(16))) args_t {
    int* a;
    int* b;
    int* c;
  } args;

  args* kernArgs = NULL;

  // get queue size
  uint32_t queue_size = 0;
  HSA_EXEC(hsa_agent_get_info(gpuAgent, HSA_AGENT_INFO_QUEUE_MAX_SIZE, &queue_size), -1);

  // create queue
  HSA_EXEC(hsa_queue_create(gpuAgent, queue_size, HSA_QUEUE_TYPE_MULTI, NULL, NULL, 0, 0, &queue), -1);

  // Find a memory pool that supports kernel arguments.
  hsa_amd_memory_pool_t kernarg_pool;
  HSA_EXEC(
    hsa_amd_agent_iterate_memory_pools(cpuAgent, GetKernArgMemoryPool, &kernarg_pool), -1);

  // Allocate the kernel argument buffer from the kernarg_pool.
  HSA_EXEC(hsa_amd_memory_pool_allocate(kernarg_pool, sizeof(kernArgs), 0,
                                            reinterpret_cast<void**>(&kernArgs)), -1);

  HSA_EXEC(hsa_amd_agents_allow_access(1, &gpuAgent, NULL, kernArgs), -1);

  kernArgs->a = src;
  kernArgs->b = write_dst;
  kernArgs->c = dst;

  InitializeGpuReadWriteKernel(&accessKernel, size / 4,  gpuAgent);

  LogPrint(LOG_DEBUG, "Loading Kernel code object\n");

  // Create the executable, get symbol by name and load the code object
  if (LoadKernelFromObjFile(&accessKernel))
    return -1;

  // create completion signal
  HSA_EXEC(hsa_signal_create(1, 0, NULL, &signal), -1);

  // create aql packet
  hsa_kernel_dispatch_packet_t aql = {};

  // initialize aql packet
  aql.workgroup_size_x = 256;
  aql.workgroup_size_y = 1;
  aql.workgroup_size_z = 1;
  aql.grid_size_x = size;
  aql.grid_size_y = 1;
  aql.grid_size_z = 1;
  aql.private_segment_size = 0;
  aql.group_segment_size = 0;
  aql.kernel_object = accessKernel.kernel_object;
  aql.kernarg_address = kernArgs;
  aql.completion_signal = signal;

  const uint32_t queue_mask = queue->size - 1;

  // write to command queue
  uint64_t index = hsa_queue_load_write_index_relaxed(queue);
  hsa_queue_store_write_index_relaxed(queue, index + 1);

  WriteAQLToQueueLoc(queue, index, &aql);

  hsa_kernel_dispatch_packet_t* q_base_addr =
    reinterpret_cast<hsa_kernel_dispatch_packet_t*>(queue->base_address);
  AtomicSetPacketHeader(
    (HSA_PACKET_TYPE_KERNEL_DISPATCH << HSA_PACKET_HEADER_TYPE) |
        (1 << HSA_PACKET_HEADER_BARRIER) |
        (HSA_FENCE_SCOPE_SYSTEM << HSA_PACKET_HEADER_ACQUIRE_FENCE_SCOPE) |
        (HSA_FENCE_SCOPE_SYSTEM << HSA_PACKET_HEADER_RELEASE_FENCE_SCOPE),
    (1 << HSA_KERNEL_DISPATCH_PACKET_SETUP_DIMENSIONS),
    reinterpret_cast<hsa_kernel_dispatch_packet_t*>(&q_base_addr[index & queue_mask]));

  LogPrint(LOG_DEBUG, "Ringing doorbell\n");
  // ringdoor bell
  hsa_signal_store_relaxed(queue->doorbell_signal, index);
  // wait for the signal and reset it for future use
  while (hsa_signal_wait_scacquire(signal, HSA_SIGNAL_CONDITION_LT, 1, (uint64_t)-1,
                                    HSA_WAIT_STATE_ACTIVE)) {
  }

  LogPrint(LOG_DEBUG, "Kernel completed\n");
  hsa_signal_store_relaxed(signal, 1);

  if (kernArgs)
      hsa_memory_free(kernArgs);

  if (queue) {
      hsa_queue_destroy(queue);
  }
  return 0;
}

int runLocal(hsa_agent_t gpuAgent) {
  int node_id;
  HSA_EXEC(hsa_agent_get_info(gpuAgent, (hsa_agent_info_t)HSA_AMD_AGENT_INFO_DRIVER_NODE_ID, &node_id), -1);
  LogPrint(LOG_INFO, "Running local process GPU node-id:%d (rank:%d)\n", node_id, gRank);

  hsa_agent_t cpuAgent;
  HSA_EXEC(hsa_agent_get_info(gpuAgent, (hsa_agent_info_t)HSA_AMD_AGENT_INFO_NEAREST_CPU, &cpuAgent), -1);

  struct test_data_t *test_data = nullptr;
  size_t alloc_size = AlignUp(sizeof(test_data_t), 4096);

  HSA_EXEC(hsa_amd_agent_iterate_memory_pools(gGpus[0], GetGlobalMemoryPool, &gDevicePool), -1);

  LogPrint(LOG_DEBUG, "Calling hsa_amd_vmem_set_access\n");
  HSA_EXEC(hsa_amd_vmem_address_reserve(reinterpret_cast<void**>(&test_data), alloc_size, 0, 0), -1);

  LogPrint(LOG_DEBUG, "Calling hsa_amd_vmem_handle_create\n");
  hsa_amd_vmem_alloc_handle_t memory_handle = {};
  HSA_EXEC(hsa_amd_vmem_handle_create(gDevicePool, alloc_size,
                                          MEMORY_TYPE_NONE, 0, &memory_handle), -1);

  LogPrint(LOG_DEBUG, "Calling hsa_amd_vmem_map\n");
  HSA_EXEC(hsa_amd_vmem_map(test_data, alloc_size, 0, memory_handle, 0), -1);

  // Give host and device access to device data
  hsa_amd_memory_access_desc_t permsAccess[] = {{HSA_ACCESS_PERMISSION_RW, gpuAgent},
                                                {HSA_ACCESS_PERMISSION_RW, cpuAgent}};

  LogPrint(LOG_DEBUG, "Calling hsa_amd_vmem_set_access\n");
  HSA_EXEC(hsa_amd_vmem_set_access(test_data, alloc_size, permsAccess, 2), -1);

  LogPrint(LOG_DEBUG, "Calling hsa_amd_memory_fill\n");
  HSA_EXEC(hsa_amd_memory_fill(test_data, 0, alloc_size/sizeof(uint32_t)), -1);

  // initialize the host buffers
  for (int i = 0; i < BUFFER_SIZE; ++i) {
    unsigned int seed = time(NULL);
    test_data->src[i] = 1 + rand_r(&seed) % 1;
    test_data->src_copy[i] = test_data->src[i];
  }

  LogPrint(LOG_DEBUG, "Launching test kernel\n");
  if (LaunchAccessDispatch(gpuAgent, cpuAgent, test_data->src, test_data->dst, test_data->write_dst, test_data->src_copy, BUFFER_SIZE)) {
    LogPrint(LOG_INFO, "Launch Dispatch failed\n");
  } else {
    LogPrint(LOG_INFO, "Launch Dispatch finished\n");
  }

  if (VerifyLocalData(test_data->src, test_data->dst, test_data->write_dst, test_data->src_copy, BUFFER_SIZE)) {
    LogPrint(LOG_INFO, "Data verification failed\n");
  } else {
    LogPrint(LOG_INFO, "Data verification successful\n");
  }

  HSA_EXEC(hsa_amd_vmem_unmap(test_data, alloc_size), -1);
  HSA_EXEC(hsa_amd_vmem_handle_release(memory_handle), -1);
  HSA_EXEC(hsa_amd_vmem_address_free(test_data, alloc_size), -1);

  return 0;
}

int runExporter(hsa_agent_t gpuAgent) {
  int node_id;
  HSA_EXEC(hsa_agent_get_info(gpuAgent, (hsa_agent_info_t)HSA_AMD_AGENT_INFO_DRIVER_NODE_ID, &node_id), -1);
  LogPrint(LOG_INFO, "Running Exporter process GPU node-id:%d (rank:%d partner-rank:%d)\n", node_id, gRank, gPartnerRank);

  hsa_agent_t cpuAgent;
  HSA_EXEC(hsa_agent_get_info(gpuAgent, (hsa_agent_info_t)HSA_AMD_AGENT_INFO_NEAREST_CPU, &cpuAgent), -1);

  struct test_data_t *test_data = nullptr;
  size_t alloc_size = AlignUp(sizeof(test_data_t), 4096);

  HSA_EXEC(hsa_amd_agent_iterate_memory_pools(gpuAgent, GetGlobalMemoryPool, &gDevicePool), -1);

  HSA_EXEC(hsa_amd_vmem_address_reserve(reinterpret_cast<void**>(&test_data), alloc_size, 0, 0), -1);

  hsa_amd_vmem_alloc_handle_t memory_handle = {};
  HSA_EXEC(hsa_amd_vmem_handle_create(gDevicePool, alloc_size,
                                          MEMORY_TYPE_NONE, 0, &memory_handle), -1);

  HSA_EXEC(hsa_amd_vmem_map(test_data, alloc_size, 0, memory_handle, 0), -1);

  // Give host and device access to device data
  hsa_amd_memory_access_desc_t permsAccess[] = {{HSA_ACCESS_PERMISSION_RW, gpuAgent},
                                                {HSA_ACCESS_PERMISSION_RW, cpuAgent}};

  HSA_EXEC(hsa_amd_vmem_set_access(test_data, alloc_size, permsAccess, 2), -1);

  LogPrint(LOG_DEBUG, "Calling hsa_amd_memory_fill\n");
  HSA_EXEC(hsa_amd_memory_fill(test_data, 0, alloc_size/sizeof(uint32_t)), -1);

  // initialize the host buffers
  for (int i = 0; i < BUFFER_SIZE; ++i) {
    unsigned int seed = time(NULL);
    test_data->src[i] = 1 + rand_r(&seed) % 1;
    test_data->src_copy[i] = test_data->src[i];
  }

  hsa_fabric_handle_t fabric_handle = {};
  //memset(fabric_handle.handle, 0x55, sizeof(fabric_handle));
  LogPrint(LOG_DEBUG, "Exporting fabric handle [memory_handle:%lx]\n", memory_handle.handle);
  HSA_EXEC(hsa_amd_vmem_export_fabric_handle(&fabric_handle, memory_handle, 0), -1);

  LogPrint(LOG_DEBUG, "Sending fabric handle to importer [%s]\n", fabric_handle_str(fabric_handle));
  MPI_Send(&fabric_handle, 16, MPI_UNSIGNED_CHAR, gPartnerRank, 0, MPI_COMM_WORLD);


  LogPrint(LOG_DEBUG, "Waiting for importer to run shader\n");
  int remote_status = -1;
  MPI_Recv(&remote_status, 1, MPI_INT, gPartnerRank, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

  if (remote_status == 0) {
    LogPrint(LOG_DEBUG, "Verifying local data is updated\n");

    if (VerifyLocalData(test_data->src, test_data->dst, test_data->write_dst, test_data->src_copy, BUFFER_SIZE)) {
      LogPrint(LOG_INFO, "Exporter Data verification FAILED\n");
    } else {
      LogPrint(LOG_INFO, "Exporter Data verification PASS\n");
    }
  } else {
    LogPrint(LOG_INFO, "Importer reported failure, skipping local data verification\n");
  }

  HSA_EXEC(hsa_amd_vmem_unmap(test_data, alloc_size), -1);
  HSA_EXEC(hsa_amd_vmem_handle_release(memory_handle), -1);
  HSA_EXEC(hsa_amd_vmem_address_free(test_data, alloc_size), -1);

  LogPrint(LOG_INFO, "Exporter process exiting\n");
  return 0;
}

int runImporter(hsa_agent_t gpuAgent) {
  int node_id;
  HSA_EXEC(hsa_agent_get_info(gpuAgent, (hsa_agent_info_t)HSA_AMD_AGENT_INFO_DRIVER_NODE_ID, &node_id), -1);
  LogPrint(LOG_INFO, "Running Importer process GPU:%d (rank:%d partner-rank:%d)\n", node_id, gRank, gPartnerRank);

  hsa_agent_t cpuAgent;
  HSA_EXEC(hsa_agent_get_info(gpuAgent, (hsa_agent_info_t)HSA_AMD_AGENT_INFO_NEAREST_CPU, &cpuAgent), -1);

  struct test_data_t *test_data = nullptr;
  size_t alloc_size = AlignUp(sizeof(test_data_t), 4096);
  HSA_EXEC(hsa_amd_vmem_address_reserve(reinterpret_cast<void**>(&test_data), alloc_size, 0, 0), -1);

  hsa_fabric_handle_t fabric_handle;
  LogPrint(LOG_DEBUG, "Waiting for fabric handle\n");
  MPI_Recv(&fabric_handle, 16, MPI_UNSIGNED_CHAR, gPartnerRank, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

  hsa_amd_vmem_alloc_handle_t memory_handle = {};
  LogPrint(LOG_DEBUG, "Importing fabric handle [%s]\n", fabric_handle_str(fabric_handle));
  HSA_EXEC(hsa_amd_vmem_import_fabric_handle(fabric_handle, &memory_handle), -1);

  LogPrint(LOG_DEBUG, "Mapping imported handle to local VA [%s]\n", fabric_handle_str(fabric_handle));
  HSA_EXEC(hsa_amd_vmem_map(test_data, alloc_size, 0, memory_handle, 0), -1);

  // Give host and device access to device data
  hsa_amd_memory_access_desc_t permsAccess[] = {{HSA_ACCESS_PERMISSION_RW, gpuAgent}};

  LogPrint(LOG_DEBUG, "Allowing RW access to local GPU [%s]\n", fabric_handle_str(fabric_handle));
  HSA_EXEC(hsa_amd_vmem_set_access(test_data, alloc_size, permsAccess, 1), -1);

  LogPrint(LOG_DEBUG, "Launching test kernel\n");
  int test_result = LaunchAccessDispatch(gpuAgent, cpuAgent, test_data->src, test_data->dst, test_data->write_dst, test_data->src_copy, BUFFER_SIZE);
  if (test_result) {
    LogPrint(LOG_INFO, "Test kernel FAILED\n");
  } else {
    LogPrint(LOG_INFO, "Test kernel launched successfully\n");
  }

  LogPrint(LOG_DEBUG, "Sending results to exporter\n");
  MPI_Send(&test_result, 1, MPI_INT, gPartnerRank, 0, MPI_COMM_WORLD);

  HSA_EXEC(hsa_amd_vmem_unmap(test_data, alloc_size), -1);
  HSA_EXEC(hsa_amd_vmem_handle_release(memory_handle), -1);
  HSA_EXEC(hsa_amd_vmem_address_free(test_data, alloc_size), -1);

  LogPrint(LOG_INFO, "Importer process exiting\n");
  return 0;
}

bool detect_multihost(int world_rank, int world_size) {
  MPI_Comm node_comm;

  MPI_Comm_split_type(MPI_COMM_WORLD, MPI_COMM_TYPE_SHARED, world_rank, MPI_INFO_NULL, &node_comm);

  int rank_on_node, size_of_node;
  MPI_Comm_rank(node_comm, &rank_on_node);
  MPI_Comm_size(node_comm, &size_of_node);
  MPI_Comm_free(&node_comm);

  return (world_size > size_of_node);
}

int main(int argc, char** argv) {
    // Initialize the MPI environment
    MPI_Init(NULL, NULL);

    // Get the number of processes
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    // Get the rank of the process
    MPI_Comm_rank(MPI_COMM_WORLD, &gRank);

    // Get the name of the processor
    int name_len;
    MPI_Get_processor_name(gProcessorName, &name_len);

    bool supp = false;
    hsa_init();
    HSA_EXEC(hsa_system_get_info(HSA_AMD_SYSTEM_INFO_VIRTUAL_MEM_API_SUPPORTED, (void*)&supp), -1);
    if (!supp) {
        LogPrint(LOG_ERROR, "Virtual Memory API not supported on this system\n");
        return -EOPNOTSUPP;
    }

    HSA_EXEC(hsa_system_get_info(HSA_AMD_SYSTEM_INFO_FABRIC_HANDLES_SUPPORTED, (void*)&supp), -1);
    if (!supp) {
        LogPrint(LOG_ERROR, "Fabric Handles not supported on this system\n");
        return -EOPNOTSUPP;
    }

    hsa_status_t err;
    HSA_EXEC(hsa_iterate_agents(IterateCPUAgents, &gCpus), -1);
    HSA_EXEC(hsa_iterate_agents(IterateGPUAgents, &gGpus), -1);

    int ret;

    auto multi_host = detect_multihost(gRank, world_size);
    if (gRank == 0)
      LogPrint(LOG_DEBUG, "Running on %s host\n", multi_host ? "multi" : "single");

    if (world_size == 1) {
      /* Self test case - no import/export fabric*/
      gPartnerRank = -1;
      ret = runLocal(gGpus[0]);
    } else if (!multi_host) {
      /* Running on a single host, avoid importer and export running on same GPU */
      auto gpuIndex = gRank % gGpus.size();
      if (!(gRank & 0x1)) {
        gPartnerRank = gRank + 1;
        ret = runExporter(gGpus[gpuIndex]);
      } else {
        gPartnerRank = gRank - 1;
        ret = runImporter(gGpus[gpuIndex]);
      }
    } else {
      if (!(gRank & 0x1)) {
        gPartnerRank = gRank + 1;
        auto gpuIndex = (gRank/2) % gGpus.size();
        ret = runExporter(gGpus[gpuIndex]);
      } else {
        gPartnerRank = gRank - 1;
        auto gpuIndex = ((gRank-1)/2) % gGpus.size();
        ret = runImporter(gGpus[gpuIndex]);
      }

    }

exit:
    // Finalize the MPI environment.
    MPI_Finalize();
    return ret;
}
