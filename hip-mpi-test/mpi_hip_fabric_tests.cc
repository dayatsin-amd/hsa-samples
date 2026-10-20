
#include "mpi_hip_fabric_helpers.hh"

struct TestCase {
    std::string name;
    TestConfig config;
};

int main(int argc, char** argv) {
    if (mpi_init_env(argc, argv)) {
        MPI_Finalize();
        return -1;
    }

    if (!check_vmm_support(0)) {
        MPI_Finalize();
        return -1;
    }

    if (gWorldSize > 1 && !check_fabric_support(0)) {
        if (gRank == 0)
            LogPrint(LOG_ERROR, "Fabric handles required for multi-rank tests but not supported\n");
        MPI_Finalize();
        return -1;
    }

    std::vector<TestCase> tests;

    /*------------------------------------------------------------------
     * Test Suite A: Buffer size sweep
     *   Exercises varying allocation sizes through the VMM + fabric path.
     *-----------------------------------------------------------------*/
    const size_t buffer_sizes[] = {1024, 4096, 8192, 32768, 65536};
    for (size_t sz : buffer_sizes) {
        char name[128];
        snprintf(name, sizeof(name), "BufferSize_%zu", sz);
        tests.push_back({name, {sz, MEMCPY_BEFORE_KERNEL, MEMCPY_SYNC}});
    }

    /*------------------------------------------------------------------
     * Test Suite B: Access order
     *   Controls whether the importer's hipMemcpy (reading src_copy from
     *   shared device memory) happens before or after the kernel dispatch.
     *-----------------------------------------------------------------*/
    tests.push_back({"AccessOrder_MemcpyBeforeKernel",
                     {1024, MEMCPY_BEFORE_KERNEL, MEMCPY_SYNC}});
    tests.push_back({"AccessOrder_KernelBeforeMemcpy",
                     {1024, KERNEL_BEFORE_MEMCPY, MEMCPY_SYNC}});

    /*------------------------------------------------------------------
     * Test Suite C: Memcpy mode (blocking vs async)
     *   Tests the importer's src_copy fetch with hipMemcpy vs
     *   hipMemcpyAsync (on a dedicated stream, synchronized before use).
     *-----------------------------------------------------------------*/
    tests.push_back({"MemcpyMode_Sync",
                     {1024, MEMCPY_BEFORE_KERNEL, MEMCPY_SYNC}});
    tests.push_back({"MemcpyMode_Async",
                     {1024, MEMCPY_BEFORE_KERNEL, MEMCPY_ASYNC}});

    int pass = 0, fail = 0;

    for (const auto& tc : tests) {
        if (gRank == 0)
            LogPrint(LOG_INFO, "\n--- Running: %s [%s] ---\n",
                     tc.name.c_str(), tc.config.to_string().c_str());

        int ret = test_runner(tc.config);

        if (ret == 0) pass++; else fail++;

        if (gRank == 0)
            LogPrint(LOG_INFO, ">>> %s: %s <<<\n",
                     tc.name.c_str(), ret ? "FAILED" : "PASS");
    }

    if (gRank == 0)
        LogPrint(LOG_INFO, "\n=== Summary: %d PASS, %d FAIL, %d TOTAL ===\n",
                 pass, fail, pass + fail);

    MPI_Finalize();
    return (fail > 0) ? 1 : 0;
}
