#!/bin/bash
export HWLOC_COMPONENTS=-gl

mpirun -n 2 -env LD_LIBRARY_PATH=../opt/rocm/lib/  -env HSA_ENABLE_SDMA=0  -host mheliosr-1b114-f01-1,mheliosr-1b114-f01-2 ./mpi_rocr_fabric_async_copy_test $1


