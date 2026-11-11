/*
 * ROCR MPI fabric handle - remote TLB shootdown ordering test.
 *
 * mpi_rocr_fabric_test exports a handle, lets the importer run a shader against
 * it, and then both ranks tear down. Nothing orders those two teardowns. The
 * importer sends its result and immediately unmaps, while the exporter verifies
 * a whole buffer before it unmaps, so in practice the importer tends to release
 * first.
 *
 * That matters because the driver sends the remote TLB shootdown from the
 * EXPORTER side, when the exported allocation is cleaned up, and only when the
 * set of live importers is non-empty. If the importer has already released, the
 * exporter's cleanup finds nothing to notify and sends nothing. So the existing
 * sample may or may not produce a remote shootdown, depending on how that race
 * lands.
 *
 * This test removes the race. The importer stays mapped until the exporter has
 * released, enforced with an explicit handshake:
 *
 *   exporter                          importer
 *   --------                          --------
 *   export handle
 *   send TAG_HANDLE          ------>  recv TAG_HANDLE
 *                                     import, map, set_access
 *                                     dispatch shader (populates TLB)
 *   recv TAG_IMPORTER_READY  <------  send TAG_IMPORTER_READY
 *   unmap + handle_release
 *     <-- importer is still mapped here, which is the whole point
 *   send TAG_EXPORTER_DONE   ------>  recv TAG_EXPORTER_DONE
 *                                     unmap + handle_release
 *   recv TAG_IMPORTER_DONE   <------  send TAG_IMPORTER_DONE
 *
 * WHAT THIS TEST CAN AND CANNOT ASSERT
 *
 * It cannot observe the shootdown. There is no userspace signal for it. What
 * this test guarantees is that the DRIVER-SIDE CONDITION is met: an exported
 * allocation is released while a remote importer still holds it. Confirming
 * that the driver then sends is a kernel-log check - see README.md.
 *
 * A clean exit therefore means "the condition was created", not "the shootdown
 * worked". Treat a pass as a precondition, not as coverage.
 *
 * Two ranks on TWO HOSTS are required. On a single host both ranks sit behind
 * the same local accelerator set, the import is short-circuited locally, no
 * remote importer is ever recorded, and no shootdown can be produced however
 * the teardown is ordered. The test detects this and says so rather than
 * reporting a meaningless pass.
 */

#include <cstring>

#include "mpi_rocr_fabric_common.hh"

enum {
  TAG_HANDLE = 0,
  TAG_IMPORTER_READY = 1,
  TAG_EXPORTER_DONE = 2,
  TAG_IMPORTER_DONE = 3,
};

/*
 * Off by default. When set, the importer touches the imported memory AFTER the
 * exporter has released it. If the remote shootdown did not happen the importer
 * reads through a stale translation into freed memory; if it did happen the
 * access raises a VM fault, which arrives at the system event handler in
 * mpi_rocr_fabric_common.hh and is logged with the faulting address. Either
 * outcome is informative and neither is a clean run, so this is a debugging aid
 * and must not be enabled in CI.
 *
 * The VM fault does NOT arrive at the queue error callback - ROCr routes
 * HSA_STATUS_ERROR_MEMORY_FAULT to Runtime::VMFaultHandler instead, and that
 * aborts the process unless a system event handler claims the event. That is
 * why this test registers one.
 */
static int gProbeAfterRelease = 0;

static int runShootdownExporter(hsa_agent_t gpuAgent) {
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

  hsa_amd_memory_access_desc_t permsAccess[] = {{HSA_ACCESS_PERMISSION_RW, gpuAgent},
                                                {HSA_ACCESS_PERMISSION_RW, cpuAgent}};

  HSA_EXEC(hsa_amd_vmem_set_access(test_data, alloc_size, permsAccess, 2), -1);

  HSA_EXEC(hsa_amd_memory_fill(test_data, 0, alloc_size/sizeof(uint32_t)), -1);

  for (int i = 0; i < BUFFER_SIZE; ++i) {
    unsigned int seed = time(NULL);
    test_data->src[i] = 1 + rand_r(&seed) % 1;
    test_data->src_copy[i] = test_data->src[i];
  }

  hsa_fabric_handle_t fabric_handle = {};
  LogPrint(LOG_DEBUG, "Exporting fabric handle [memory_handle:%lx]\n", memory_handle.handle);
  HSA_EXEC(hsa_amd_vmem_export_fabric_handle(&fabric_handle, memory_handle, 0), -1);

  LogPrint(LOG_DEBUG, "Sending fabric handle to importer [%s]\n", fabric_handle_str(fabric_handle));
  MPI_Send(&fabric_handle, 16, MPI_UNSIGNED_CHAR, gPartnerRank, TAG_HANDLE, MPI_COMM_WORLD);

  LogPrint(LOG_DEBUG, "Waiting for importer to map and touch the memory\n");
  int importer_ready = -1;
  MPI_Recv(&importer_ready, 1, MPI_INT, gPartnerRank, TAG_IMPORTER_READY, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

  if (importer_ready != 0) {
    LogPrint(LOG_ERROR, "Importer failed to map the handle, nothing to test\n");
    HSA_EXEC(hsa_amd_vmem_unmap(test_data, alloc_size), -1);
    HSA_EXEC(hsa_amd_vmem_handle_release(memory_handle), -1);
    HSA_EXEC(hsa_amd_vmem_address_free(test_data, alloc_size), -1);
    return -1;
  }

  /*
   * The importer is mapped and has populated its TLB. Release now. This is the
   * event that must make the driver notify the remote importer.
   */
  LogPrint(LOG_INFO, "Releasing exported allocation while the importer still holds it\n");
  HSA_EXEC(hsa_amd_vmem_unmap(test_data, alloc_size), -1);
  HSA_EXEC(hsa_amd_vmem_handle_release(memory_handle), -1);
  LogPrint(LOG_INFO, "Exporter released\n");

  int ack = 0;
  MPI_Send(&ack, 1, MPI_INT, gPartnerRank, TAG_EXPORTER_DONE, MPI_COMM_WORLD);

  int importer_result = -1;
  MPI_Recv(&importer_result, 1, MPI_INT, gPartnerRank, TAG_IMPORTER_DONE, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

  HSA_EXEC(hsa_amd_vmem_address_free(test_data, alloc_size), -1);

  if (importer_result != 0) {
    LogPrint(LOG_INFO, "Importer reported failure\n");
    return -1;
  }

  LogPrint(LOG_INFO, "Exporter process exiting\n");
  return 0;
}

static int runShootdownImporter(hsa_agent_t gpuAgent) {
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
  MPI_Recv(&fabric_handle, 16, MPI_UNSIGNED_CHAR, gPartnerRank, TAG_HANDLE, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

  hsa_amd_vmem_alloc_handle_t memory_handle = {};
  LogPrint(LOG_DEBUG, "Importing fabric handle [%s]\n", fabric_handle_str(fabric_handle));
  HSA_EXEC(hsa_amd_vmem_import_fabric_handle(fabric_handle, &memory_handle), -1);

  LogPrint(LOG_DEBUG, "Mapping imported handle to local VA\n");
  HSA_EXEC(hsa_amd_vmem_map(test_data, alloc_size, 0, memory_handle, 0), -1);

  hsa_amd_memory_access_desc_t permsAccess[] = {{HSA_ACCESS_PERMISSION_RW, gpuAgent}};
  HSA_EXEC(hsa_amd_vmem_set_access(test_data, alloc_size, permsAccess, 1), -1);

  /*
   * Run the shader before announcing readiness. The point is to get the remote
   * translations into this GPU's TLBs, so that the exporter's release has
   * something to invalidate.
   */
  LogPrint(LOG_DEBUG, "Launching test kernel to populate remote translations\n");
  int ready = LaunchAccessDispatch(gpuAgent, cpuAgent, test_data->src, test_data->dst,
                                   test_data->write_dst, test_data->src_copy, BUFFER_SIZE);
  if (ready) {
    LogPrint(LOG_INFO, "Test kernel FAILED, reporting to exporter\n");
  }

  MPI_Send(&ready, 1, MPI_INT, gPartnerRank, TAG_IMPORTER_READY, MPI_COMM_WORLD);
  if (ready) {
    HSA_EXEC(hsa_amd_vmem_unmap(test_data, alloc_size), -1);
    HSA_EXEC(hsa_amd_vmem_handle_release(memory_handle), -1);
    HSA_EXEC(hsa_amd_vmem_address_free(test_data, alloc_size), -1);
    return -1;
  }

  /*
   * Hold the import across the exporter's release. Do not unmap before this
   * recv completes - that is the ordering the whole test exists to enforce.
   */
  LogPrint(LOG_INFO, "Holding the import while the exporter releases\n");
  int ack = -1;
  MPI_Recv(&ack, 1, MPI_INT, gPartnerRank, TAG_EXPORTER_DONE, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
  LogPrint(LOG_INFO, "Exporter has released, importer was still mapped throughout\n");

  int probe_failed = 0;

  if (gProbeAfterRelease) {
    LogPrint(LOG_INFO, "Probing freed remote memory - a fault here is an expected outcome\n");
    int probe = LaunchAccessDispatch(gpuAgent, cpuAgent, test_data->src, test_data->dst,
                                     test_data->write_dst, test_data->src_copy, BUFFER_SIZE);
    probe_failed = (probe != 0);
    LogPrint(LOG_INFO, "Post-release probe returned %d (-1 means the dispatch reported a "
                       "fault, which is what a shootdown should produce; -2 means it "
                       "simply did not finish, which proves nothing)\n", probe);
    if (probe_failed) {
      LogPrint(LOG_ERROR, "This rank's GPU queues are now evicted with no restore - "
                          "no further dispatch will run in this process\n");
    }
  }

  /*
   * Tear down and complete the handshake even after a faulted probe. The
   * exporter is blocked in MPI_Recv on TAG_IMPORTER_DONE, so returning early
   * here would turn a diagnostic run into a two-rank hang. That is why these
   * three do not use HSA_EXEC, which returns on failure: unmapping an import
   * whose exporter has already released it is exactly the call a post-release
   * run is most likely to fail, and failing it must not skip the send.
   */
  hsa_status_t teardown;

  teardown = hsa_amd_vmem_unmap(test_data, alloc_size);
  if (teardown != HSA_STATUS_SUCCESS) {
    LogPrint(LOG_ERROR, "vmem_unmap failed:%d, continuing to the handshake\n", teardown);
    probe_failed = 1;
  }

  teardown = hsa_amd_vmem_handle_release(memory_handle);
  if (teardown != HSA_STATUS_SUCCESS) {
    LogPrint(LOG_ERROR, "vmem_handle_release failed:%d, continuing to the handshake\n", teardown);
    probe_failed = 1;
  }

  teardown = hsa_amd_vmem_address_free(test_data, alloc_size);
  if (teardown != HSA_STATUS_SUCCESS) {
    LogPrint(LOG_ERROR, "vmem_address_free failed:%d, continuing to the handshake\n", teardown);
    probe_failed = 1;
  }

  int result = probe_failed ? -1 : 0;
  MPI_Send(&result, 1, MPI_INT, gPartnerRank, TAG_IMPORTER_DONE, MPI_COMM_WORLD);

  LogPrint(LOG_INFO, "Importer process exiting\n");
  return result;
}

static void usage(const char *argv0) {
  printf("usage: mpirun -n 2 -host <hostA>,<hostB> %s [--probe-after-release]\n"
         "\n"
         "  Releases an exported fabric allocation while a remote importer is\n"
         "  still mapped, which is the condition the driver needs in order to\n"
         "  send a remote TLB shootdown.\n"
         "\n"
         "  --probe-after-release  importer touches the memory after the\n"
         "                         exporter released it. Debugging aid, expect\n"
         "                         a fault or a hang. Not for CI.\n",
         argv0);
}

int main(int argc, char** argv) {
  MPI_Init(&argc, &argv);

  int world_size;
  MPI_Comm_size(MPI_COMM_WORLD, &world_size);
  MPI_Comm_rank(MPI_COMM_WORLD, &gRank);

  int name_len;
  MPI_Get_processor_name(gProcessorName, &name_len);

  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--probe-after-release")) {
      gProbeAfterRelease = 1;
    } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
      if (gRank == 0) usage(argv[0]);
      MPI_Finalize();
      return 0;
    } else {
      if (gRank == 0) {
        LogPrint(LOG_ERROR, "Unknown argument: %s\n", argv[i]);
        usage(argv[0]);
      }
      MPI_Finalize();
      return -EINVAL;
    }
  }

  if (world_size != 2) {
    if (gRank == 0) {
      LogPrint(LOG_ERROR, "This test needs exactly 2 ranks, got %d\n", world_size);
      usage(argv[0]);
    }
    MPI_Finalize();
    return -EINVAL;
  }

  bool supp = false;
  int ret = 0;

  hsa_init();

  /*
   * Must come before any dispatch. A VM fault with no handler registered aborts
   * the process, which would take the --probe-after-release case with it.
   */
  if (RegisterSystemEventHandler() != HSA_STATUS_SUCCESS) {
    LogPrint(LOG_ERROR, "Failed to register the system event handler\n");
    MPI_Finalize();
    return -EIO;
  }

  if (hsa_system_get_info(HSA_AMD_SYSTEM_INFO_VIRTUAL_MEM_API_SUPPORTED, (void*)&supp) != HSA_STATUS_SUCCESS || !supp) {
    LogPrint(LOG_ERROR, "Virtual Memory API not supported on this system\n");
    MPI_Finalize();
    return -EOPNOTSUPP;
  }

  /*
   * This is an AND reduction over every GPU agent in this process. A single
   * render node without the ualink sysfs entry turns it false for the whole
   * host, so a false here does not mean the fabric is absent everywhere.
   */
  if (hsa_system_get_info(HSA_AMD_SYSTEM_INFO_FABRIC_HANDLES_SUPPORTED, (void*)&supp) != HSA_STATUS_SUCCESS || !supp) {
    LogPrint(LOG_ERROR, "Fabric Handles not supported on this system\n");
    MPI_Finalize();
    return -EOPNOTSUPP;
  }

  if (hsa_iterate_agents(IterateCPUAgents, &gCpus) != HSA_STATUS_SUCCESS ||
      hsa_iterate_agents(IterateGPUAgents, &gGpus) != HSA_STATUS_SUCCESS ||
      gGpus.empty()) {
    LogPrint(LOG_ERROR, "Failed to enumerate agents\n");
    MPI_Finalize();
    return -ENODEV;
  }

  /*
   * Both ranks on one host means the import is satisfied locally, no remote
   * importer is recorded, and no shootdown can be produced. Say so instead of
   * reporting a pass that proves nothing.
   */
  if (!detect_multihost(gRank, world_size)) {
    if (gRank == 0) {
      LogPrint(LOG_ERROR,
               "Both ranks are on one host. The import is satisfied locally and no remote\n");
      LogPrint(LOG_ERROR,
               "shootdown can be produced. Launch with: mpirun -n 2 -host <hostA>,<hostB>\n");
    }
    MPI_Finalize();
    return -EOPNOTSUPP;
  }

  if (!(gRank & 0x1)) {
    gPartnerRank = gRank + 1;
    ret = runShootdownExporter(gGpus[0]);
  } else {
    gPartnerRank = gRank - 1;
    ret = runShootdownImporter(gGpus[0]);
  }

  if (gRank == 0) {
    LogPrint(LOG_INFO, "%s - the exporter released while a remote importer was mapped.\n",
             ret ? "FAILED" : "CONDITION CREATED");
    LogPrint(LOG_INFO, "Check the exporter host kernel log to confirm the driver sent the shootdown.\n");
  }

  MPI_Finalize();
  return ret;
}
