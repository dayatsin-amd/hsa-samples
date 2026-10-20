#pragma once

#include <mpi.h>
#include <hip/hip_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <vector>
#include <string>

/*==========================================================================
 * Test Configuration
 *=========================================================================*/

enum LogLevel {
    LOG_ERROR = 0,
    LOG_INFO  = 1,
    LOG_DEBUG = 2,
};

enum AccessOrder {
    MEMCPY_BEFORE_KERNEL = 0,
    KERNEL_BEFORE_MEMCPY = 1,
};

enum MemcpyMode {
    MEMCPY_SYNC  = 0,
    MEMCPY_ASYNC = 1,
};

struct TestConfig {
    size_t bufferSize;
    AccessOrder accessOrder;
    MemcpyMode memcpyMode;

    std::string to_string() const {
        char buf[256];
        snprintf(buf, sizeof(buf), "bufSize=%zu order=%s memcpy=%s",
                 bufferSize,
                 accessOrder == MEMCPY_BEFORE_KERNEL ? "memcpy_first" : "kernel_first",
                 memcpyMode == MEMCPY_SYNC ? "sync" : "async");
        return buf;
    }
};

/*==========================================================================
 * Dynamic Test Data Layout
 *   Memory layout: [src | dst | write_dst | src_copy], each bufferSize ints.
 *=========================================================================*/

struct TestDataLayout {
    size_t bufferSize;
    size_t total_size;

    TestDataLayout(size_t bs) : bufferSize(bs), total_size(4 * bs * sizeof(int)) {}

    int* src(void* base) const {
        return reinterpret_cast<int*>(base);
    }
    int* dst(void* base) const {
        return reinterpret_cast<int*>(static_cast<char*>(base) + bufferSize * sizeof(int));
    }
    int* write_dst(void* base) const {
        return reinterpret_cast<int*>(static_cast<char*>(base) + 2 * bufferSize * sizeof(int));
    }
    int* src_copy(void* base) const {
        return reinterpret_cast<int*>(static_cast<char*>(base) + 3 * bufferSize * sizeof(int));
    }
};

/*==========================================================================
 * Globals
 *=========================================================================*/

inline int gVerboseLevel = LOG_DEBUG;
inline char gProcessorName[MPI_MAX_PROCESSOR_NAME];
inline int gRank = -1;
inline int gPartnerRank = -1;
inline int gNumGpus = 0;
inline int gWorldSize = 0;
inline bool gMultiHost = false;

/*==========================================================================
 * Logging
 *=========================================================================*/

inline void log_printf(const char* file, int line, const char* format, ...) {
    va_list ap;
    va_start(ap, format);
    char message[4096];
    vsnprintf(message, sizeof(message), format, ap);
    va_end(ap);
    printf("[%s|%d] (%s:%d) %s", gProcessorName, gRank, file, line, message);
    fflush(stdout);
}

#define LogPrint(verbose, format, ...)                                          \
    do {                                                                        \
        if (verbose <= gVerboseLevel) {                                         \
            log_printf(__FILE__, __LINE__, format, ##__VA_ARGS__);              \
        }                                                                       \
    } while (false)

#define HIP_CHECK(cmd)                                                          \
    do {                                                                        \
        hipError_t error = (cmd);                                               \
        if (error != hipSuccess) {                                              \
            LogPrint(LOG_ERROR, "HIP error: '%s'(%d) from '%s'\n",             \
                     hipGetErrorString(error), error, #cmd);                    \
            return -1;                                                          \
        }                                                                       \
    } while (0)

/*==========================================================================
 * Capability Checks
 *=========================================================================*/

inline bool check_vmm_support(int device) {
    int value = 0;
    if (hipDeviceGetAttribute(&value,
            hipDeviceAttributeVirtualMemoryManagementSupported, device)
        != hipSuccess || !value) {
        LogPrint(LOG_ERROR, "VMM not supported on device %d\n", device);
        return false;
    }
    return true;
}

inline bool check_fabric_support(int device) {
    int value = 0;
    if (hipDeviceGetAttribute(&value,
            hipDeviceAttributeHandleTypeFabricSupported, device)
        != hipSuccess || !value) {
        LogPrint(LOG_ERROR, "Fabric handles not supported on device %d\n", device);
        return false;
    }
    return true;
}

/*==========================================================================
 * Helpers
 *=========================================================================*/

template <typename T>
static T AlignUp(T value, size_t alignment) {
    return (T)(((size_t)value + alignment - 1) / alignment * alignment);
}

inline char fabric_str_buf[256];
inline const char* fabric_handle_str(const hipMemFabricHandle_t& handle) {
    char* p = fabric_str_buf;
    for (size_t i = 0; i < sizeof(handle.data) && i < 64; i++)
        p += sprintf(p, "%02x ", handle.data[i]);
    return fabric_str_buf;
}

/*==========================================================================
 * GPU Kernel: reads src into dst, writes index pattern into write_dst
 *=========================================================================*/

__global__ void gpuReadWrite(const int* src, int* write_dst, int* dst, size_t length) {
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < length) {
        dst[idx] = src[idx];
        write_dst[idx] = (int)idx;
    }
}

/*==========================================================================
 * Memcpy wrapper: supports both sync and async modes
 *=========================================================================*/

inline int DeviceMemcpy(void* dst, const void* src, size_t size,
                        hipMemcpyKind kind, MemcpyMode mode) {
    if (mode == MEMCPY_ASYNC) {
        hipStream_t stream;
        HIP_CHECK(hipStreamCreate(&stream));
        HIP_CHECK(hipMemcpyAsync(dst, src, size, kind, stream));
        HIP_CHECK(hipStreamSynchronize(stream));
        HIP_CHECK(hipStreamDestroy(stream));
    } else {
        HIP_CHECK(hipMemcpy(dst, src, size, kind));
    }
    return 0;
}

/*==========================================================================
 * Data Verification
 *=========================================================================*/

inline int VerifyData(const int* dst, const int* write_dst,
                      const int* src_copy, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (dst[i] != src_copy[i]) {
            LogPrint(LOG_ERROR, "dst verification failed index:%zu dst:%d expected:%d\n",
                     i, dst[i], src_copy[i]);
            return -1;
        }
    }
    LogPrint(LOG_DEBUG, "GPU copied data to dst successfully\n");

    for (size_t i = 0; i < size; i++) {
        if (write_dst[i] != (int)i) {
            LogPrint(LOG_ERROR, "write_dst verification failed index:%zu got:%d expected:%d\n",
                     i, write_dst[i], (int)i);
            return -1;
        }
    }
    LogPrint(LOG_DEBUG, "GPU wrote data to write_dst successfully\n");
    return 0;
}

/*==========================================================================
 * VMM Allocation Management
 *=========================================================================*/

struct VmmAllocation {
    void* dptr;
    size_t size;
    hipMemGenericAllocationHandle_t memHandle;
    hipMemAllocationProp prop;
    size_t granularity;
};

inline int VmmAllocAndMap(VmmAllocation* alloc, int deviceId,
                          hipMemAllocationHandleType handleType,
                          size_t requestedSize) {
    memset(&alloc->prop, 0, sizeof(alloc->prop));
    alloc->prop.type = hipMemAllocationTypePinned;
    alloc->prop.location.type = hipMemLocationTypeDevice;
    alloc->prop.location.id = deviceId;
    alloc->prop.requestedHandleType = handleType;

    alloc->granularity = 0;
    HIP_CHECK(hipMemGetAllocationGranularity(&alloc->granularity, &alloc->prop,
                                              hipMemAllocationGranularityMinimum));

    alloc->size = AlignUp(requestedSize, alloc->granularity);
    LogPrint(LOG_DEBUG, "VMM alloc: requested=%zu aligned=%zu granularity=%zu handleType=0x%x\n",
             requestedSize, alloc->size, alloc->granularity, handleType);

    alloc->dptr = nullptr;
    HIP_CHECK(hipMemAddressReserve(&alloc->dptr, alloc->size, alloc->granularity, nullptr, 0));
    HIP_CHECK(hipMemCreate(&alloc->memHandle, alloc->size, &alloc->prop, 0));
    HIP_CHECK(hipMemMap(alloc->dptr, alloc->size, 0, alloc->memHandle, 0));

    hipMemAccessDesc accessDesc = {};
    accessDesc.location = alloc->prop.location;
    accessDesc.flags = hipMemAccessFlagsProtReadWrite;
    HIP_CHECK(hipMemSetAccess(alloc->dptr, alloc->size, &accessDesc, 1));

    return 0;
}

inline int VmmReserveAndMapImported(VmmAllocation* alloc, int deviceId,
                                    hipMemGenericAllocationHandle_t importedHandle,
                                    size_t requestedSize) {
    memset(&alloc->prop, 0, sizeof(alloc->prop));
    alloc->prop.type = hipMemAllocationTypePinned;
    alloc->prop.location.type = hipMemLocationTypeDevice;
    alloc->prop.location.id = deviceId;
    alloc->prop.requestedHandleType = hipMemHandleTypeFabric;

    alloc->granularity = 0;
    HIP_CHECK(hipMemGetAllocationGranularity(&alloc->granularity, &alloc->prop,
                                              hipMemAllocationGranularityMinimum));

    alloc->size = AlignUp(requestedSize, alloc->granularity);
    alloc->memHandle = importedHandle;

    alloc->dptr = nullptr;
    HIP_CHECK(hipMemAddressReserve(&alloc->dptr, alloc->size, alloc->granularity, nullptr, 0));
    HIP_CHECK(hipMemMap(alloc->dptr, alloc->size, 0, alloc->memHandle, 0));

    hipMemAccessDesc accessDesc = {};
    accessDesc.location = alloc->prop.location;
    accessDesc.flags = hipMemAccessFlagsProtReadWrite;
    HIP_CHECK(hipMemSetAccess(alloc->dptr, alloc->size, &accessDesc, 1));

    LogPrint(LOG_DEBUG, "VMM import mapped: size=%zu dptr=%p\n", alloc->size, alloc->dptr);
    return 0;
}

inline int VmmFree(VmmAllocation* alloc) {
    if (alloc->dptr) {
        HIP_CHECK(hipMemUnmap(alloc->dptr, alloc->size));
        HIP_CHECK(hipMemRelease(alloc->memHandle));
        HIP_CHECK(hipMemAddressFree(alloc->dptr, alloc->size));
        alloc->dptr = nullptr;
    }
    return 0;
}

/*==========================================================================
 * Initialize test data on host and copy to device
 *=========================================================================*/

inline int InitTestData(void* dptr, const TestDataLayout& layout,
                        std::vector<int>& host_src_copy) {
    size_t bs = layout.bufferSize;
    host_src_copy.resize(bs);

    std::vector<char> host_buf(layout.total_size, 0);
    void* hbase = host_buf.data();

    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)gRank;
    for (size_t i = 0; i < bs; i++) {
        int val = 1 + rand_r(&seed) % 100;
        layout.src(hbase)[i] = val;
        layout.src_copy(hbase)[i] = val;
        host_src_copy[i] = val;
    }

    HIP_CHECK(hipMemcpy(dptr, hbase, layout.total_size, hipMemcpyHostToDevice));
    return 0;
}

/*==========================================================================
 * RunKernelAndVerify
 *   When host_src_copy is nullptr (importer path), fetches src_copy from
 *   device memory. The fetch order relative to the kernel dispatch is
 *   controlled by config.accessOrder, and sync/async by config.memcpyMode.
 *   When host_src_copy is provided (local/exporter path), skips the fetch.
 *=========================================================================*/

inline int RunKernelAndVerify(int deviceId, void* dptr, const TestDataLayout& layout,
                              const TestConfig& config,
                              const int* host_src_copy = nullptr) {
    HIP_CHECK(hipSetDevice(deviceId));

    bool need_fetch = (host_src_copy == nullptr);
    std::vector<int> fetched_src_copy;
    if (need_fetch)
        fetched_src_copy.resize(layout.bufferSize);

    /* Optionally fetch src_copy BEFORE kernel */
    if (need_fetch && config.accessOrder == MEMCPY_BEFORE_KERNEL) {
        LogPrint(LOG_DEBUG, "Fetching src_copy from device (before kernel, %s)\n",
                 config.memcpyMode == MEMCPY_ASYNC ? "async" : "sync");
        if (DeviceMemcpy(fetched_src_copy.data(), layout.src_copy(dptr),
                         layout.bufferSize * sizeof(int),
                         hipMemcpyDeviceToHost, config.memcpyMode))
            return -1;
    }

    /* Launch kernel */
    dim3 block(256);
    dim3 grid((layout.bufferSize + block.x - 1) / block.x);
    LogPrint(LOG_DEBUG, "Launching GPU kernel (device:%d bufferSize:%zu)\n",
             deviceId, layout.bufferSize);
    gpuReadWrite<<<grid, block>>>(layout.src(dptr), layout.write_dst(dptr),
                                   layout.dst(dptr), layout.bufferSize);
    HIP_CHECK(hipGetLastError());
    HIP_CHECK(hipDeviceSynchronize());

    /* Optionally fetch src_copy AFTER kernel */
    if (need_fetch && config.accessOrder == KERNEL_BEFORE_MEMCPY) {
        LogPrint(LOG_DEBUG, "Fetching src_copy from device (after kernel, %s)\n",
                 config.memcpyMode == MEMCPY_ASYNC ? "async" : "sync");
        if (DeviceMemcpy(fetched_src_copy.data(), layout.src_copy(dptr),
                         layout.bufferSize * sizeof(int),
                         hipMemcpyDeviceToHost, config.memcpyMode))
            return -1;
    }

    const int* verify_src = need_fetch ? fetched_src_copy.data() : host_src_copy;

    /* Readback dst and write_dst, then verify */
    std::vector<int> h_dst(layout.bufferSize);
    std::vector<int> h_write_dst(layout.bufferSize);
    HIP_CHECK(hipMemcpy(h_dst.data(), layout.dst(dptr),
                         layout.bufferSize * sizeof(int), hipMemcpyDeviceToHost));
    HIP_CHECK(hipMemcpy(h_write_dst.data(), layout.write_dst(dptr),
                         layout.bufferSize * sizeof(int), hipMemcpyDeviceToHost));

    return VerifyData(h_dst.data(), h_write_dst.data(), verify_src, layout.bufferSize);
}

/*==========================================================================
 * VerifyDeviceResults
 *   Used by exporter to check shared memory after importer's kernel ran.
 *=========================================================================*/

inline int VerifyDeviceResults(void* dptr, const TestDataLayout& layout,
                               const int* host_src_copy) {
    std::vector<int> h_dst(layout.bufferSize);
    std::vector<int> h_write_dst(layout.bufferSize);
    HIP_CHECK(hipMemcpy(h_dst.data(), layout.dst(dptr),
                         layout.bufferSize * sizeof(int), hipMemcpyDeviceToHost));
    HIP_CHECK(hipMemcpy(h_write_dst.data(), layout.write_dst(dptr),
                         layout.bufferSize * sizeof(int), hipMemcpyDeviceToHost));
    return VerifyData(h_dst.data(), h_write_dst.data(), host_src_copy, layout.bufferSize);
}

/*==========================================================================
 * Mode 1: Local self-test (world_size == 1)
 *=========================================================================*/

inline int runLocal(int deviceId, const TestConfig& config) {
    TestDataLayout layout(config.bufferSize);
    LogPrint(LOG_INFO, "=== Local self-test (device:%d rank:%d %s) ===\n",
             deviceId, gRank, config.to_string().c_str());
    HIP_CHECK(hipSetDevice(deviceId));

    VmmAllocation alloc = {};
    if (VmmAllocAndMap(&alloc, deviceId, hipMemHandleTypeNone, layout.total_size))
        return -1;

    std::vector<int> host_src_copy;
    if (InitTestData(alloc.dptr, layout, host_src_copy))
        return -1;

    int ret = RunKernelAndVerify(deviceId, alloc.dptr, layout, config,
                                  host_src_copy.data());
    LogPrint(LOG_INFO, "Local test: %s\n", ret ? "FAILED" : "PASS");

    VmmFree(&alloc);
    return ret;
}

/*==========================================================================
 * Mode 2 & 3: Exporter
 *=========================================================================*/

inline int runExporter(int deviceId, const TestConfig& config) {
    TestDataLayout layout(config.bufferSize);
    LogPrint(LOG_INFO, "=== Exporter (device:%d rank:%d partner:%d %s) ===\n",
             deviceId, gRank, gPartnerRank, config.to_string().c_str());
    HIP_CHECK(hipSetDevice(deviceId));

    VmmAllocation alloc = {};
    if (VmmAllocAndMap(&alloc, deviceId, hipMemHandleTypeFabric, layout.total_size))
        return -1;

    std::vector<int> host_src_copy;
    if (InitTestData(alloc.dptr, layout, host_src_copy))
        return -1;

    hipMemFabricHandle_t fabricHandle = {};
    LogPrint(LOG_DEBUG, "Exporting fabric handle\n");
    HIP_CHECK(hipMemExportToShareableHandle(&fabricHandle, alloc.memHandle,
                                             hipMemHandleTypeFabric, 0));

    LogPrint(LOG_DEBUG, "Sending fabric handle to importer [%s]\n",
             fabric_handle_str(fabricHandle));
    MPI_Send(&fabricHandle, sizeof(fabricHandle), MPI_UNSIGNED_CHAR,
             gPartnerRank, 0, MPI_COMM_WORLD);

    LogPrint(LOG_DEBUG, "Waiting for importer result\n");
    int remote_status = -1;
    MPI_Recv(&remote_status, 1, MPI_INT, gPartnerRank, 0,
             MPI_COMM_WORLD, MPI_STATUS_IGNORE);

    int ret = 0;
    if (remote_status == 0) {
        LogPrint(LOG_DEBUG, "Verifying local data updated by remote kernel\n");
        ret = VerifyDeviceResults(alloc.dptr, layout, host_src_copy.data());
        LogPrint(LOG_INFO, "Exporter verification: %s\n", ret ? "FAILED" : "PASS");
    } else {
        LogPrint(LOG_INFO, "Importer reported failure, skipping local verification\n");
        ret = -1;
    }

    VmmFree(&alloc);
    LogPrint(LOG_INFO, "Exporter exiting\n");
    return ret;
}

/*==========================================================================
 * Mode 2 & 3: Importer
 *   The src_copy fetch from device is now handled inside RunKernelAndVerify.
 *   config.accessOrder controls whether the fetch happens before or after
 *   the kernel dispatch. config.memcpyMode selects sync vs async memcpy.
 *=========================================================================*/

inline int runImporter(int deviceId, const TestConfig& config) {
    TestDataLayout layout(config.bufferSize);
    LogPrint(LOG_INFO, "=== Importer (device:%d rank:%d partner:%d %s) ===\n",
             deviceId, gRank, gPartnerRank, config.to_string().c_str());
    HIP_CHECK(hipSetDevice(deviceId));

    hipMemFabricHandle_t fabricHandle = {};
    LogPrint(LOG_DEBUG, "Waiting for fabric handle from exporter\n");
    MPI_Recv(&fabricHandle, sizeof(fabricHandle), MPI_UNSIGNED_CHAR,
             gPartnerRank, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

    LogPrint(LOG_DEBUG, "Received fabric handle [%s]\n", fabric_handle_str(fabricHandle));

    hipMemGenericAllocationHandle_t memHandle;
    HIP_CHECK(hipMemImportFromShareableHandle(&memHandle, &fabricHandle,
                                               hipMemHandleTypeFabric));

    VmmAllocation alloc = {};
    if (VmmReserveAndMapImported(&alloc, deviceId, memHandle, layout.total_size))
        return -1;

    /*
     * host_src_copy is nullptr → RunKernelAndVerify will fetch src_copy
     * from device, ordered relative to kernel per config.accessOrder,
     * using sync or async memcpy per config.memcpyMode.
     */
    int test_result = RunKernelAndVerify(deviceId, alloc.dptr, layout, config);
    LogPrint(LOG_INFO, "Importer verification: %s\n", test_result ? "FAILED" : "PASS");

    LogPrint(LOG_DEBUG, "Sending result to exporter\n");
    MPI_Send(&test_result, 1, MPI_INT, gPartnerRank, 0, MPI_COMM_WORLD);

    VmmFree(&alloc);
    LogPrint(LOG_INFO, "Importer exiting\n");
    return test_result;
}

/*==========================================================================
 * Multi-host Detection
 *=========================================================================*/

inline bool detect_multihost(int world_rank, int world_size) {
    MPI_Comm node_comm;
    MPI_Comm_split_type(MPI_COMM_WORLD, MPI_COMM_TYPE_SHARED,
                        world_rank, MPI_INFO_NULL, &node_comm);
    int size_of_node;
    MPI_Comm_size(node_comm, &size_of_node);
    MPI_Comm_free(&node_comm);
    return (world_size > size_of_node);
}

/*==========================================================================
 * MPI Environment Init
 *=========================================================================*/

inline int mpi_init_env(int argc, char** argv) {
    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &gWorldSize);
    MPI_Comm_rank(MPI_COMM_WORLD, &gRank);

    int name_len;
    MPI_Get_processor_name(gProcessorName, &name_len);

    if (hipGetDeviceCount(&gNumGpus) != hipSuccess || gNumGpus == 0) {
        LogPrint(LOG_ERROR, "No HIP GPUs found\n");
        return -1;
    }

    gMultiHost = detect_multihost(gRank, gWorldSize);

    LogPrint(LOG_INFO, "Processor:%s rank:%d world_size:%d GPUs:%d multi_host:%d\n",
             gProcessorName, gRank, gWorldSize, gNumGpus, gMultiHost);
    return 0;
}

/*==========================================================================
 * Test Runner
 *   Selects mode based on world_size and topology, then dispatches to
 *   runLocal / runExporter / runImporter with the given config.
 *=========================================================================*/

inline int test_runner(const TestConfig& config) {
    int ret = 0;

    if (gWorldSize == 1) {
        gPartnerRank = -1;
        ret = runLocal(0, config);

    } else if (!gMultiHost) {
        int gpuIndex = gRank % gNumGpus;
        if (!(gRank & 0x1)) {
            gPartnerRank = gRank + 1;
            ret = runExporter(gpuIndex, config);
        } else {
            gPartnerRank = gRank - 1;
            ret = runImporter(gpuIndex, config);
        }
    } else {
        if (!(gRank & 0x1)) {
            gPartnerRank = gRank + 1;
            int gpuIndex = (gRank / 2) % gNumGpus;
            ret = runExporter(gpuIndex, config);
        } else {
            gPartnerRank = gRank - 1;
            int gpuIndex = ((gRank - 1) / 2) % gNumGpus;
            ret = runImporter(gpuIndex, config);
        }
    }

    return ret;
}
