#!/bin/bash
export HWLOC_COMPONENTS=-gl
export LD_LIBRARY_PATH=~/hsa-samples-private/

hostname=`hostname`

mpirun -n 1 -env LD_LIBRARY_PATH=~/hsa-samples-private/ -env HSA_ENABLE_SDMA=0 -host $hostname ./mpi_rocr_fabric_test

