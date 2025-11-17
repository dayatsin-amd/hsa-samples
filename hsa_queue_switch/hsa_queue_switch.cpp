/*
* Copyright © Advanced Micro Devices, Inc., or its affiliates.
*
* SPDX-License-Identifier: MIT
*/

#include "hsa.h"
#include "hsa_ext_amd.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <vector>
#include <random>
#include <thread>
#include <chrono>

#define CHECK(x) do { if((x) != HSA_STATUS_SUCCESS) { assert(false); abort(); } } while(false);

struct Device {
  hsa_agent_t agent;
};
std::vector<hsa_agent_t> all_devices;

// Assumes bitfield layout is little endian.
// Assumes std::atomic<uint16_t> is binary compatible with uint16_t and uses HW atomics.
union AqlHeader {
  struct {
    uint16_t type     : 8;
    uint16_t barrier  : 1;
    uint16_t acquire  : 2;
    uint16_t release  : 2;
    uint16_t reserved : 3;
  };
  uint16_t raw;
};

union Aql {
  AqlHeader header;
  hsa_barrier_and_packet_t barrier_and;
};

std::vector<Device> gpu;

bool DeviceDiscovery() {
  hsa_status_t err;

  err = hsa_iterate_agents([](hsa_agent_t agent, void*) {
    hsa_status_t err;

    hsa_device_type_t type;
    err = hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE, &type);
    CHECK(err);

    if(type == HSA_DEVICE_TYPE_GPU) {
      Device dev;
      dev.agent = agent;
      gpu.push_back(dev);
      all_devices.push_back(agent);
    }

    return HSA_STATUS_SUCCESS;
  }, nullptr);

  if(gpu.empty())
    return false;
  return true;
}

// Not for parallel insertion.
bool SubmitPacket(hsa_queue_t* queue, Aql& pkt) {
  size_t mask = queue->size - 1;
  Aql* ring = (Aql*)queue->base_address;

  uint64_t write = hsa_queue_load_write_index_relaxed(queue);
  uint64_t read = hsa_queue_load_read_index_relaxed(queue);
  if(write - read + 1 > queue->size)
    return false;

  Aql& dst = ring[write & mask];

  uint16_t header = pkt.header.raw;
  pkt.header.raw = dst.header.raw;
  dst = pkt;
  __atomic_store_n(&dst.header.raw, header, __ATOMIC_RELEASE);
  pkt.header.raw = header;

  hsa_queue_store_write_index_release(queue, write+1);
  hsa_signal_store_screlease(queue->doorbell_signal, write);

  return true;
}

int main(int argc, char* argv[]) {
  int device_index=0;

  // Print usage if help is requested
  if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
    printf("Usage: %s [options]\n", argv[0]);
    printf("Options:\n");
    printf("  -t          Run 10 iterations with tabulated output to show variation\n");
    printf("  -d          Create 3 dummy queues between queue1 and queue2\n");
    printf("  -p          Set queue2 to high priority\n");
    printf("  -h, --help  Show this help message\n");
    printf("  (default)   Run 100 iterations and show only averages\n");
    printf("\nOptions can be combined, e.g., %s -t -d -p\n", argv[0]);
    return 0;
  }

  hsa_status_t err;
  err = hsa_init();
  CHECK(err);

  if(!DeviceDiscovery()) {
    printf("Usable devices not found.\n");
    return 0;
  }

  uint64_t freq;
  err = hsa_system_get_info(HSA_SYSTEM_INFO_TIMESTAMP_FREQUENCY, &freq);
  CHECK(err);

  // Check for dummy queues and priority options
  bool create_dummy_queues = false;
  bool set_high_priority = false;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-d") == 0) {
      create_dummy_queues = true;
    }
    if (strcmp(argv[i], "-p") == 0) {
      set_high_priority = true;
    }
  }

  // Create two queues (with optional dummy queues in between)
  hsa_queue_t *queue1, *queue2;
  hsa_queue_t *dummy1 = nullptr, *dummy2 = nullptr, *dummy3 = nullptr;

  err = hsa_queue_create(gpu[device_index].agent, 1024, HSA_QUEUE_TYPE_MULTI, nullptr, nullptr, 0, 0, &queue1);
  CHECK(err);

  // Create dummy queues between queue1 and queue2 so that it gets mapped to same pipe underneath
  if (create_dummy_queues) {
    printf("Creating 3 dummy queues between queue1 and queue2...\n");
    err = hsa_queue_create(gpu[device_index].agent, 1024, HSA_QUEUE_TYPE_MULTI, nullptr, nullptr, 0, 0, &dummy1);
    CHECK(err);
    err = hsa_queue_create(gpu[device_index].agent, 1024, HSA_QUEUE_TYPE_MULTI, nullptr, nullptr, 0, 0, &dummy2);
    CHECK(err);
    err = hsa_queue_create(gpu[device_index].agent, 1024, HSA_QUEUE_TYPE_MULTI, nullptr, nullptr, 0, 0, &dummy3);
    CHECK(err);
  }

  err = hsa_queue_create(gpu[device_index].agent, 1024, HSA_QUEUE_TYPE_MULTI, nullptr, nullptr, 0, 0, &queue2);
  CHECK(err);

  // Set queue2 priority if requested
  if (set_high_priority) {
    printf("Setting queue2 to HIGH priority...\n");
    err = hsa_amd_queue_set_priority(queue2, HSA_AMD_QUEUE_PRIORITY_HIGH);
    CHECK(err);
  }

  // Enable profiling on both queues
  err = hsa_amd_profiling_set_profiler_enabled(queue1, true);
  CHECK(err);
  err = hsa_amd_profiling_set_profiler_enabled(queue2, true);
  CHECK(err);

  // Create shared dependency signal and completion signals for barriers
  hsa_signal_t shared_signal, completion1, completion2;
  err = hsa_signal_create(1, 0, nullptr, &shared_signal);
  CHECK(err);
  err = hsa_signal_create(1, 0, nullptr, &completion1);
  CHECK(err);
  err = hsa_signal_create(1, 0, nullptr, &completion2);
  CHECK(err);

  uint64_t systemTsf = 0;
  hsa_system_get_info(HSA_SYSTEM_INFO_TIMESTAMP_FREQUENCY, &systemTsf);
  printf("System timestamp frequency = %" PRIu64 " Hz\n", systemTsf);
  double ticksTotime = 1e9/(double)systemTsf; // Convert ticks to nanoseconds

  // Random number generator for random delays
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> delay_dist(1, 1000); // 1-1000 microseconds

  // Check for tabulated output option
  bool tabulated = false;
  int Ntests = 100;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-t") == 0) {
      tabulated = true;
      Ntests = 10;
      break;
    }
  }

  printf("\n========== Queue Switch Test ==========\n");

  // Variables to track averages for non-tabulated mode
  double sum_q1_trig_to_end = 0.0;
  double sum_q2_trig_to_end = 0.0;
  double sum_completion_diff = 0.0;

  if (tabulated) {
    printf("Running %d iterations with tabulated output...\n\n", Ntests);
    printf("%-4s | %-9s | %-13s | %-13s | %-13s || %-13s | %-13s | %-13s || %-13s\n",
           "Iter", "Delay(us)", "Q1:Trig->St", "Q1:Exec", "Q1:Trig->End",
           "Q2:Trig->St", "Q2:Exec", "Q2:Trig->End", "Q1-Q2 Diff");
    printf("-----+-----------+---------------+---------------+---------------++---------------+---------------+---------------++---------------\n");
  } else {
    printf("Running %d iterations...\n\n", Ntests);
  }

  auto dispatch_barrier = [&](hsa_queue_t* queue, hsa_signal_t dep, hsa_signal_t signal) {
    Aql packet = {0};
    packet.header.type = HSA_PACKET_TYPE_BARRIER_AND;
    packet.header.barrier = 1;
    packet.header.acquire = HSA_FENCE_SCOPE_SYSTEM;
    packet.header.release = HSA_FENCE_SCOPE_SYSTEM;

    packet.barrier_and.dep_signal[0] = dep;
    packet.barrier_and.completion_signal = signal;

    SubmitPacket(queue, packet);
  };

  for (int iter = 0; iter < Ntests; ++iter) {
    // Reset signals
    hsa_signal_store_relaxed(shared_signal, 1);
    hsa_signal_store_relaxed(completion1, 1);
    hsa_signal_store_relaxed(completion2, 1);

    // Submit barriers to both queues that wait on the same shared signal
    dispatch_barrier(queue1, shared_signal, completion1);
    dispatch_barrier(queue2, shared_signal, completion2);

    // Random delay before triggering the signal (in microseconds)
    int delay_us = delay_dist(gen);
    std::this_thread::sleep_for(std::chrono::microseconds(delay_us));

    // Capture the timestamp just before triggering the signal
    uint64_t trigger_time = 0;
    hsa_system_get_info(HSA_SYSTEM_INFO_TIMESTAMP, &trigger_time);

    // Trigger the shared signal (write 0 to release both barriers)
    hsa_signal_store_release(shared_signal, 0);

    // Wait for both barriers to complete
    hsa_signal_wait_acquire(completion1, HSA_SIGNAL_CONDITION_EQ, 0, -1, HSA_WAIT_STATE_ACTIVE);
    hsa_signal_wait_acquire(completion2, HSA_SIGNAL_CONDITION_EQ, 0, -1, HSA_WAIT_STATE_ACTIVE);

    // Get profiling timestamps for both barriers
    hsa_amd_profiling_dispatch_time_t barrier1_ts = {};
    hsa_amd_profiling_dispatch_time_t barrier2_ts = {};

    err = hsa_amd_profiling_get_dispatch_time(gpu[device_index].agent, completion1, &barrier1_ts);
    CHECK(err);
    err = hsa_amd_profiling_get_dispatch_time(gpu[device_index].agent, completion2, &barrier2_ts);
    CHECK(err);

    // Calculate latencies (in microseconds) - use signed arithmetic to avoid wraparound
    // Latency from trigger to barrier completion
    double latency1_trigger_to_end = ((int64_t)barrier1_ts.end - (int64_t)trigger_time) * ticksTotime / 1000.0;
    double latency2_trigger_to_end = ((int64_t)barrier2_ts.end - (int64_t)trigger_time) * ticksTotime / 1000.0;

    // Latency from trigger to barrier start (time to begin processing)
    double latency1_trigger_to_start = ((int64_t)barrier1_ts.start - (int64_t)trigger_time) * ticksTotime / 1000.0;
    double latency2_trigger_to_start = ((int64_t)barrier2_ts.start - (int64_t)trigger_time) * ticksTotime / 1000.0;

    // Barrier execution time (from start to end)
    double barrier1_exec_time = ((int64_t)barrier1_ts.end - (int64_t)barrier1_ts.start) * ticksTotime / 1000.0;
    double barrier2_exec_time = ((int64_t)barrier2_ts.end - (int64_t)barrier2_ts.start) * ticksTotime / 1000.0;

    // Time difference between the two barriers completing (use absolute value)
    int64_t completion_diff_ticks = (int64_t)barrier2_ts.end - (int64_t)barrier1_ts.end;
    double completion_time_diff = (completion_diff_ticks < 0 ? -completion_diff_ticks : completion_diff_ticks) * ticksTotime / 1000.0;

    if (tabulated) {
      printf("%-4d | %9d | %10.3f us | %10.3f us | %10.3f us || %10.3f us | %10.3f us | %10.3f us || %10.3f us\n",
             iter, delay_us,
             latency1_trigger_to_start, barrier1_exec_time, latency1_trigger_to_end,
             latency2_trigger_to_start, barrier2_exec_time, latency2_trigger_to_end,
             completion_time_diff);
    } else {
      // Accumulate for averages (no per-iteration output)
      sum_q1_trig_to_end += latency1_trigger_to_end;
      sum_q2_trig_to_end += latency2_trigger_to_end;
      sum_completion_diff += completion_time_diff;
    }
  }

  if (tabulated) {
    printf("\n");
  } else {
    // Print averages for non-tabulated mode
    printf("========================================\n");
    printf("Average Statistics over %d iterations:\n", Ntests);
    printf("  Q1 Trigger->End:       %8.3f us\n", sum_q1_trig_to_end / Ntests);
    printf("  Q2 Trigger->End:       %8.3f us\n", sum_q2_trig_to_end / Ntests);
    printf("  Q1-Q2 Difference:      %8.3f us\n", sum_completion_diff / Ntests);
    printf("========================================\n\n");
  }

  // Cleanup
  hsa_signal_destroy(shared_signal);
  hsa_signal_destroy(completion1);
  hsa_signal_destroy(completion2);
  hsa_queue_destroy(queue1);
  hsa_queue_destroy(queue2);

  if (create_dummy_queues) {
    hsa_queue_destroy(dummy1);
    hsa_queue_destroy(dummy2);
    hsa_queue_destroy(dummy3);
  }

  err = hsa_shut_down();
  CHECK(err);

  printf("Test completed successfully!\n");
  return 0;
}


