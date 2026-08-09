#!/bin/bash
export HWLOC_COMPONENTS=-gl

mpirun -n 2 -env LD_LIBRARY_PATH=/opt/rocm  -env HSA_ENABLE_SDMA=1  -host mheliosr-1b114-f05-1,mheliosr-1b114-f05-2 ./mpi_rocr_fabric_async_copy_test $1


