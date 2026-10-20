# HIP MPI based Fabric Handle Test for IFoE bringup

1. This test uses MPI to export/import Fabric handles between different hosts
2. Fabric handle is mapped to a va range on import side.
3. A kernel launch uses the mapped va to copy data into the device ptr.
4. Export side validates the device ptr for expected data.

**Follow instructions in main README for mpi setup**

**Steps to compile this sample**
1. Before compiling, make sure MPI is installed.
2. Update Makefile with correct path for rocm installation.
   
```
cd hsa-samples/hip-mpi-test
make
```

**Steps to run this sample**

Run on localhost with single rank - self test, no fabric handle used
```
mpirun -n 1 -host localhost ./mpi_hip_fabric_test
```

Run with 1 exporter and 1 importer on same host
```
mpirun -n 2 -host <host1> ./mpi_hip_fabric_test
```

Run with 1 exporter and 1 importer on 2 different hosts
```
mpirun -n 2 -host host1,host2 ./mpi_hip_fabric_test
```
