/*
 * Shared helpers for the ROCR MPI fabric handle samples.
 *
 * Extracted from mpi_rocr_fabric_test.cc, which still carries its own copy and
 * does not include this header. The samples build one translation unit per
 * executable, so the definitions here are not marked inline.
 *
 * One deliberate deviation from the original, so the two have now diverged:
 * LaunchAccessDispatch reports a failed dispatch instead of waiting on it
 * forever. It registers a queue error callback, the wait is bounded, and
 * RegisterSystemEventHandler covers the VM fault case, which the queue callback
 * does not see. See the comments on the callbacks below.
 */
#pragma once




#include <mpi.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <atomic>
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

/*
 * Set by the error callbacks, read by the dispatch loop below. Both callbacks
 * run on a runtime-owned thread, so the handshake has to be atomic.
 *
 * File scope on purpose: the queue is handed a pointer to this, and the error
 * paths out of LaunchAccessDispatch return without destroying the queue. A
 * stack object would leave the runtime holding a dangling pointer.
 */
struct dispatch_error_t {
  std::atomic<bool> raised;
  /*
   * Atomic too. The system event handler is live for the whole process, so a
   * late fault from one dispatch can land while the next one is resetting this.
   */
  std::atomic<hsa_status_t> status;
};

static dispatch_error_t gDispatchError;

/*
 * Queue error callback. The runtime puts the queue in the error state and calls
 * this for a bad packet, an illegal instruction, an aperture violation, or an
 * out-of-resources condition. A dispatch on a queue that has entered the error
 * state never satisfies its completion signal, so without this the sample
 * cannot tell an errored queue from a slow kernel.
 *
 * Note what this does NOT cover: a plain page-not-present VM fault, which is
 * what a dispatch against released memory produces. ROCr routes that away from
 * the per-queue callback - AqlQueue::ExceptionHandler returns early on
 * HSA_STATUS_ERROR_MEMORY_FAULT and defers to Runtime::VMFaultHandler. That is
 * what the system event handler below is for.
 */
void QueueErrorCallback(hsa_status_t status, hsa_queue_t *source, void *data) {
  const char *errorStr = NULL;
  hsa_status_string(status, &errorStr);
  LogPrint(LOG_ERROR, "Queue error callback: status:%d %s\n", status,
           errorStr ? errorStr : "unknown error");

  if (data == NULL)
    return;

  dispatch_error_t *error = static_cast<dispatch_error_t*>(data);
  error->status.store(status, std::memory_order_relaxed);
  error->raised.store(true, std::memory_order_release);
}

/*
 * System event handler, where the VM fault actually arrives. It is active only
 * in a sample that calls RegisterSystemEventHandler below; the other two in
 * this directory do not, and still abort on a fault.
 *
 * Returning HSA_STATUS_SUCCESS is load-bearing: Runtime::VMFaultHandler aborts
 * the process unless a registered handler returns success. Without this the
 * sample dies with SIGABRT on a post-release access instead of reporting it.
 *
 * TWO LIMITS WORTH KNOWING, both properties of the runtime, not of this file:
 *
 *  - ONE FAULT PER PROCESS. VMFaultHandler returns false once it has handled a
 *    fault, and the async events loop drops a handler that returns false. A
 *    second fault is therefore never reported. The dispatch wait below is
 *    capped for exactly this reason.
 *  - THE NODE'S QUEUES DO NOT COME BACK. KFD evicts the process's queues on the
 *    faulting device and arms no restore, so no further dispatch will run on
 *    this rank. Surviving the fault buys diagnosis, not recovery.
 *
 * The faulting virtual address is logged because it is the useful assertion -
 * it should land inside the imported range.
 */
hsa_status_t SystemEventHandler(const hsa_amd_event_t *event, void *data) {
  if (event == NULL || event->event_type != HSA_AMD_GPU_MEMORY_FAULT_EVENT)
    return HSA_STATUS_ERROR;

  LogPrint(LOG_ERROR, "GPU memory fault at virtual address:0x%lx reason-mask:0x%x\n",
           event->memory_fault.virtual_address, event->memory_fault.fault_reason_mask);

  if (data != NULL) {
    dispatch_error_t *error = static_cast<dispatch_error_t*>(data);
    error->status.store((hsa_status_t)HSA_STATUS_ERROR_MEMORY_FAULT,
                        std::memory_order_relaxed);
    error->raised.store(true, std::memory_order_release);
  }

  /* Tell the runtime the fault was handled, so that it does not abort. */
  return HSA_STATUS_SUCCESS;
}

/*
 * Call once, after hsa_init() and before any dispatch.
 */
hsa_status_t RegisterSystemEventHandler() {
  gDispatchError.status.store(HSA_STATUS_SUCCESS, std::memory_order_relaxed);
  gDispatchError.raised.store(false, std::memory_order_relaxed);
  return hsa_amd_register_system_event_handler(SystemEventHandler, &gDispatchError);
}

/*
 * Returns 0 on a completed dispatch, -1 when an error or a fault was reported,
 * and -2 when the dispatch neither completed nor reported anything before the
 * deadline below. The last two are kept apart on purpose: -2 is not evidence of
 * a fault, and only the first VM fault in a process is ever reported.
 */
int LaunchAccessDispatch(hsa_agent_t gpuAgent, hsa_agent_t cpuAgent, int *src, int *dst, int *write_dst, int *src_copy, size_t size) {
  hsa_queue_t* queue = NULL;  // command queue
  hsa_signal_t signal = {0};  // completion signal

  gDispatchError.status.store(HSA_STATUS_SUCCESS, std::memory_order_relaxed);
  gDispatchError.raised.store(false, std::memory_order_relaxed);

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

  // create queue, with an error callback so a queue error is reported
  HSA_EXEC(hsa_queue_create(gpuAgent, queue_size, HSA_QUEUE_TYPE_MULTI,
                            QueueErrorCallback, &gDispatchError, 0, 0, &queue), -1);

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
  /*
   * Wait in slices, with an overall deadline, rather than one infinite wait. A
   * dispatch that errors or faults never satisfies its completion signal, so
   * the original infinite wait could only hang.
   *
   * The deadline is not belt-and-braces. The runtime reports only the FIRST VM
   * fault per process, so a second faulting dispatch satisfies neither the
   * signal nor the error flag, and a loop with no cap would spin forever.
   *
   * The timeout is in system-timestamp ticks, which are nanoseconds on Linux.
   */
  const uint64_t wait_slice = 100ULL * 1000ULL * 1000ULL; /* 100 ms */
  const int max_slices = 100;                             /* 10 s overall */
  int slices = 0;
  int dispatch_failed = 0;

  while (hsa_signal_wait_scacquire(signal, HSA_SIGNAL_CONDITION_LT, 1, wait_slice,
                                    HSA_WAIT_STATE_BLOCKED)) {
    if (gDispatchError.raised.load(std::memory_order_acquire)) {
      dispatch_failed = -1;
      LogPrint(LOG_ERROR, "Dispatch did not complete, reported error:%d\n",
               (int)gDispatchError.status.load(std::memory_order_relaxed));
      break;
    }

    if (++slices >= max_slices) {
      dispatch_failed = -2;
      LogPrint(LOG_ERROR,
               "Dispatch did not complete and no error was reported within %d ms. "
               "Note that only the first VM fault in a process is reported.\n",
               (int)(max_slices * (wait_slice / 1000000ULL)));
      break;
    }
  }

  if (!dispatch_failed) {
    LogPrint(LOG_DEBUG, "Kernel completed\n");
  }
  hsa_signal_store_relaxed(signal, 1);

  if (kernArgs)
      hsa_memory_free(kernArgs);

  if (queue) {
      hsa_queue_destroy(queue);
  }
  return dispatch_failed;
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
