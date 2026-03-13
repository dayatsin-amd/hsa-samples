/*
* Copyright © Advanced Micro Devices, Inc., or its affiliates.
*
* SPDX-License-Identifier: MIT
*/

#include "hsa/hsa.h"
#include "hsa/hsa_ext_amd.h"

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
  const int device_index = 0;
  const int num_iters = 10;


  hsa_status_t err;
  CHECK(hsa_init());

  if(!DeviceDiscovery()) {
    printf("Usable devices not found.\n");
    return 0;
  }

  hsa_queue_t *queue;

  CHECK(hsa_queue_create(gpu[0].agent, 1024, HSA_QUEUE_TYPE_MULTI, nullptr, nullptr, 0, 0, &queue));

  // Enable profiling on both queues
  CHECK(hsa_amd_profiling_set_profiler_enabled(queue, true));

  // Create shared dependency signal and completion signals for barriers
  hsa_signal_t completion;
  err = hsa_signal_create(1, 0, nullptr, &completion);

  auto dispatch_barrier = [&](hsa_queue_t* queue, hsa_signal_t signal) {
    Aql packet = {};
    packet.header.type = HSA_PACKET_TYPE_BARRIER_AND;
    packet.header.barrier = 1;
    packet.header.acquire = HSA_FENCE_SCOPE_SYSTEM;
    packet.header.release = HSA_FENCE_SCOPE_SYSTEM;

    packet.barrier_and.completion_signal = signal;

    SubmitPacket(queue, packet);
  };

  auto get_signal_raw_ts = [&](hsa_signal_t signal, uint64_t *start_ts, uint64_t *end_ts) {
    const uint64_t start_ts_offset = 32;
    const uint64_t end_ts_offset = 40;
    *start_ts = *(uint64_t*)((uint8_t*)signal.handle + start_ts_offset);
    *end_ts = *(uint64_t*)((uint8_t*)signal.handle + end_ts_offset);
  };

  uint64_t start_ts, end_ts;
  hsa_amd_clock_counters_t clock_counters = {};

  for (int iter = 0; iter < num_iters; ++iter) {
    // Reset signals
    hsa_signal_store_relaxed(completion, 1);
    dispatch_barrier(queue, completion);
    hsa_signal_wait_acquire(completion, HSA_SIGNAL_CONDITION_EQ, 0, -1, HSA_WAIT_STATE_ACTIVE);

    get_signal_raw_ts(completion, &start_ts, &end_ts);

    CHECK(hsa_agent_get_info(gpu[0].agent, (hsa_agent_info_t)HSA_AMD_AGENT_INFO_CLOCK_COUNTERS, &clock_counters));

    printf("iter:%d AQL ts.start:%lx ts.end:%lx gpu_clock_counter:%lx (delta:%lx) \n",
        iter, start_ts, end_ts, clock_counters.gpu_clock_counter,
        (int64_t)clock_counters.gpu_clock_counter - start_ts);
  }


  // Cleanup
  hsa_signal_destroy(completion);
  hsa_queue_destroy(queue);

  CHECK(hsa_shut_down());

  printf("Test completed successfully!\n");
  return 0;
}


