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
#include <utility>
#include <cstring>


#include "hsa/hsa_ext_amd.h"
#include "hsa/hsa.h"

enum {
    LOG_ERROR,
    LOG_INFO,
    LOG_DEBUG,
} verbose_level;

/* Global variables */

int gVerboseLevel = LOG_INFO;
char gProcessorName[MPI_MAX_PROCESSOR_NAME];
int gRank = -1;
int gPartnerRank = -1;
std::vector<hsa_agent_t> gCpus;
std::vector<hsa_agent_t> gGpus;
hsa_amd_memory_pool_t gDevicePool = {};

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
    #ifdef PRINT_FILE_LINE
    printf("[%s|%d] (%s:%d) %s",
          gProcessorName, gRank, file, line, message);
    #else
    printf("[%s|%d] %s",
          gProcessorName, gRank, message);
    #endif
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

template <typename T>
static  T AlignDown(T value, uint64_t alignment) {
  return (T)((value / alignment) * alignment);
}

template <typename T>
static  T AlignUp(T value, uint64_t alignment) {
  return AlignDown((T)(value + alignment - 1), alignment);
}


static bool gdb_attached = false;
void wait_for_gdb() {
  LogPrint(LOG_INFO, "Waiting for GDB to attach...\n");
  while (!gdb_attached) {
    usleep(100000);
  }
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

int runExporter(hsa_agent_t gpuAgent, std::pair<uint64_t, std::string> copy_size) {
  int node_id;
  HSA_EXEC(hsa_agent_get_info(gpuAgent, (hsa_agent_info_t)HSA_AMD_AGENT_INFO_DRIVER_NODE_ID, &node_id), -1);
  LogPrint(LOG_DEBUG, "Running Exporter process GPU node-id:%d (rank:%d partner-rank:%d)\n", node_id, gRank, gPartnerRank);
  LogPrint(LOG_INFO, "\n------------------------------------------------\n");
  LogPrint(LOG_INFO, "Test starting for size:%s\n", copy_size.second.c_str());
  LogPrint(LOG_INFO, "\n------------------------------------------------\n");

  hsa_agent_t cpuAgent;
  HSA_EXEC(hsa_agent_get_info(gpuAgent, (hsa_agent_info_t)HSA_AMD_AGENT_INFO_NEAREST_CPU, &cpuAgent), -1);

  /* We allocate 2X copy size:
   * Exporter will initialize first half buffer to 1,2,3,4...
   * Importer will copy first half onto second half 
   * Exporter will verify that second half has 1,2,3,4,...
   */
  uint64_t alloc_size = AlignUp(copy_size.first, 4096);
  void *test_buffer = nullptr;

  HSA_EXEC(hsa_amd_agent_iterate_memory_pools(gpuAgent, GetGlobalMemoryPool, &gDevicePool), -1);

  HSA_EXEC(hsa_amd_vmem_address_reserve(reinterpret_cast<void**>(&test_buffer), alloc_size, 0, 0), -1);

  hsa_amd_vmem_alloc_handle_t memory_handle = {};
  HSA_EXEC(hsa_amd_vmem_handle_create(gDevicePool, alloc_size,
                                          MEMORY_TYPE_NONE, 0, &memory_handle), -1);

  HSA_EXEC(hsa_amd_vmem_map(test_buffer, alloc_size, 0, memory_handle, 0), -1);

  // Give host and device access to device data
  hsa_amd_memory_access_desc_t permsAccess[] = {{HSA_ACCESS_PERMISSION_RW, gpuAgent},
                                                {HSA_ACCESS_PERMISSION_RW, cpuAgent}};

  HSA_EXEC(hsa_amd_vmem_set_access(test_buffer, alloc_size, permsAccess, 2), -1);

  HSA_EXEC(hsa_amd_memory_fill(test_buffer, 0, alloc_size/sizeof(uint32_t)), -1);

  uint8_t *src_ptr =  reinterpret_cast<uint8_t*>(test_buffer);

  // initialize the first half of the buffers
  for (uint64_t i = 0; i < copy_size.first/2; ++i) {
    src_ptr[i] = (i & 0xFF);
  }

  hsa_fabric_handle_t fabric_handle = {};
  LogPrint(LOG_DEBUG, "Exporting fabric handle [memory_handle:%lx]\n", memory_handle.handle);
  HSA_EXEC(hsa_amd_vmem_export_fabric_handle(&fabric_handle, memory_handle, 0), -1);

  size_t copy_size_bytes = copy_size.first;
  MPI_Send(&copy_size_bytes, 1, MPI_UINT64_T, gPartnerRank, 0, MPI_COMM_WORLD);


  LogPrint(LOG_DEBUG, "Sending fabric handle to importer [%s]\n", fabric_handle_str(fabric_handle));
  MPI_Send(&fabric_handle, 16, MPI_UNSIGNED_CHAR, gPartnerRank, 0, MPI_COMM_WORLD);


  LogPrint(LOG_DEBUG, "Waiting for importer to finish async copy\n");
  int remote_status = -1;
  MPI_Recv(&remote_status, 1, MPI_INT, gPartnerRank, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

  bool test_result = true;

  if (remote_status == 0) {
    LogPrint(LOG_INFO, "Importer finished, verifying data\n");
    uint8_t *verify_ptr = reinterpret_cast<uint8_t*>(test_buffer) + (copy_size.first/2);

    for (uint64_t i = 0; i < copy_size.first/2; ++i) {
      if ((verify_ptr[i]) != (i & 0xFF)) {
        LogPrint(LOG_INFO, "Data verification failed on exporter at index[%d] val:%08x expected:%08x\n", i, verify_ptr[i], (i & 0xFF));
	test_result = false;
        goto exit;
      }
    }
  } else {
    LogPrint(LOG_INFO, "Importer reported failure, skipping local data verification\n");
    test_result = false;
  }

exit:
  HSA_EXEC(hsa_amd_vmem_unmap(test_buffer, alloc_size), -1);
  HSA_EXEC(hsa_amd_vmem_handle_release(memory_handle), -1);
  HSA_EXEC(hsa_amd_vmem_address_free(test_buffer, alloc_size), -1);

  LogPrint(LOG_DEBUG, "Exporter process exiting\n");
  LogPrint(LOG_INFO, "\n------------------------------------------------\n");
  LogPrint(LOG_INFO, "Data verification size:%s %s\n", copy_size.second.c_str(), test_result ? "PASS" : "FAIL");
  LogPrint(LOG_INFO, "\n------------------------------------------------\n");
  return 0;
}

int runImporter(hsa_agent_t gpuAgent) {
  int node_id;
  int test_result = 0;
  HSA_EXEC(hsa_agent_get_info(gpuAgent, (hsa_agent_info_t)HSA_AMD_AGENT_INFO_DRIVER_NODE_ID, &node_id), -1);
  LogPrint(LOG_INFO, "Running Importer process GPU:%d (rank:%d partner-rank:%d)\n", node_id, gRank, gPartnerRank);

  hsa_signal_t completion_signal = {};

  HSA_EXEC(hsa_signal_create(1, 0, nullptr, &completion_signal), -1);

  hsa_agent_t cpuAgent;
  HSA_EXEC(hsa_agent_get_info(gpuAgent, (hsa_agent_info_t)HSA_AMD_AGENT_INFO_NEAREST_CPU, &cpuAgent), -1);

  size_t copy_size_bytes = 0;

  MPI_Recv(&copy_size_bytes, 1, MPI_UINT64_T, gPartnerRank, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
  LogPrint(LOG_DEBUG, "Received copy size bytes: %zu\n", copy_size_bytes);

  size_t alloc_size = AlignUp(copy_size_bytes, 4096);

  struct test_data_t *test_buffer = nullptr;
  HSA_EXEC(hsa_amd_vmem_address_reserve(reinterpret_cast<void**>(&test_buffer), alloc_size, 0, 0), -1);
  hsa_fabric_handle_t fabric_handle;
  LogPrint(LOG_DEBUG, "Waiting for fabric handle\n");
  MPI_Recv(&fabric_handle, 16, MPI_UNSIGNED_CHAR, gPartnerRank, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

  hsa_amd_vmem_alloc_handle_t memory_handle = {};
  LogPrint(LOG_DEBUG, "Importing fabric handle [%s]\n", fabric_handle_str(fabric_handle));
  HSA_EXEC(hsa_amd_vmem_import_fabric_handle(fabric_handle, &memory_handle), -1);

  LogPrint(LOG_DEBUG, "Mapping handle to local VA [%s]\n", fabric_handle_str(fabric_handle));
  HSA_EXEC(hsa_amd_vmem_map(test_buffer, alloc_size, 0, memory_handle, 0), -1);

  // Give host and device access to device data
  hsa_amd_memory_access_desc_t permsAccess[] = {{HSA_ACCESS_PERMISSION_RW, gpuAgent}};

  HSA_EXEC(hsa_amd_vmem_set_access(test_buffer, alloc_size, permsAccess, 1), -1);

  uint8_t *src_ptr =  reinterpret_cast<uint8_t*>(test_buffer);
  uint8_t *dest_ptr = reinterpret_cast<uint8_t*>(test_buffer) + (copy_size_bytes/2);

  //Create dummy queue to create a VMID.
  hsa_queue_t* queue = nullptr;
  uint32_t queue_size = 16384;
  HSA_EXEC(hsa_queue_create(gpuAgent, queue_size, HSA_QUEUE_TYPE_MULTI, NULL, NULL, 0, 0, &queue), -1);

  LogPrint(LOG_INFO, "Buffer VA on importer is: %p\n", src_ptr);
  const char* path = std::getenv("WAIT_FOR_GDB");
  if (path && strcmp(path, "1") == 0) {
    wait_for_gdb();
  }

  LogPrint(LOG_INFO, "Starting memory copy %d bytes\n", copy_size_bytes/2);
  /* If we set src and dst agents as same agent, this will force a blit copy, so
   * set the dest agent as a CPU agent to prefer SDMA engines in ROCr */
  HSA_EXEC(hsa_amd_memory_async_copy(dest_ptr, cpuAgent, src_ptr, gpuAgent, (copy_size_bytes / 2), 0, NULL, completion_signal), -1);

  while(hsa_signal_wait_acquire(completion_signal, HSA_SIGNAL_CONDITION_LT, 1, -1, HSA_WAIT_STATE_ACTIVE));
  LogPrint(LOG_INFO, "Memory copy finished\n");

exit:

  LogPrint(LOG_DEBUG, "Sending results to exporter\n");
  MPI_Send(&test_result, 1, MPI_INT, gPartnerRank, 0, MPI_COMM_WORLD);

  HSA_EXEC(hsa_amd_vmem_unmap(test_buffer, alloc_size), -1);
  HSA_EXEC(hsa_amd_vmem_handle_release(memory_handle), -1);
  HSA_EXEC(hsa_amd_vmem_address_free(test_buffer, alloc_size), -1);

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

    size_t user_copy_size = 0;

    if (argc > 1) {
      char lastChar = argv[1][strlen(argv[1]) - 1];
      char sizeStr[16] = "";

      size_t multiplier = 1;
      switch (lastChar) {
        case 'K':
          multiplier = 1024;
          break;
        case 'M':
          multiplier = 1024 * 1024;
          break;
        case 'G':
          multiplier = 1024 * 1024 * 1024;
          break;
        default:
          multiplier = 1;
          break;
      }
      if (multiplier == 1)
        strncpy(sizeStr, argv[1], strlen(argv[1]));
      else
        strncpy(sizeStr, argv[1], strlen(argv[1]) - 1);

      user_copy_size = strtoul(sizeStr, NULL, 10) * multiplier;
    }

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

    auto run_copy = [&](std::pair<uint64_t, std::string> copy_size) {
      if (world_size == 1) {
        LogPrint(LOG_ERROR, "Need at least 2 workers\n");
        return -1;
      } else if (!multi_host) {
        /* Running on a single host, avoid importer and export running on same GPU */
        auto gpuIndex = gRank % gGpus.size();
        if (!(gRank & 0x1)) {
          gPartnerRank = gRank + 1;
          return runExporter(gGpus[gpuIndex], copy_size);
        } else {
          gPartnerRank = gRank - 1;
          return runImporter(gGpus[gpuIndex]);
        }
      } else {
        if (!(gRank & 0x1)) {
          gPartnerRank = gRank + 1;
          auto gpuIndex = (gRank/2) % gGpus.size();
          return runExporter(gGpus[gpuIndex], copy_size);
        } else {
          gPartnerRank = gRank - 1;
          auto gpuIndex = ((gRank-1)/2) % gGpus.size();
          return runImporter(gGpus[gpuIndex]);
        }
      }
      return 0;
    };

    if (user_copy_size) {
      ret = run_copy(std::make_pair(user_copy_size, argv[1]));
    } else {
      std::vector<std::pair<uint64_t, std::string>> copySizes = {
        { 4096,             "4K" },
        { 8*1024,           "8K" },
        { 16*1024,          "16K" },
        { 32*1024,          "32K" },
        { 64*1024,          "64K" },
        { 128*1024,         "128K" },
        { 256*1024,         "256K" },
        { 512*1024,         "512K" },
        { 1*1024*1024,      "1MB" },
        { 2*1024*1024,      "2MB" },
        { 4*1024*1024,      "4MB" },
        { 8*1024*1024,      "8MB" },
        { 16*1024*1024,     "16MB" },
        { 32*1024*1024,     "32MB" },
        { 32*1024*1024,     "64MB" },        
        { 128*1024*1024,    "128M" },
        { 256*1024*1024,    "256M" },
        { 512*1024*1024,    "512M" }

      };

      for (auto copySize: copySizes) {
        ret = run_copy(copySize);
        if (ret != 0) 
          break;
      }
    }
exit:
    // Finalize the MPI environment.
    MPI_Finalize();
    return ret;
}
