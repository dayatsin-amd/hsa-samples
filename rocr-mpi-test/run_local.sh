#!/bin/bash
export HWLOC_COMPONENTS=-gl

hostname=`hostname`

mpirun -n 1 -env LD_LIBRARY_PATH=/opt/rocm -env HSA_ENABLE_SDMA=0 -host $hostname ./mpi_rocr_fabric_test

