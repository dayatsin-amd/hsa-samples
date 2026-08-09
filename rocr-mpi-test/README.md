# ROCr/HSA MPI based Fabric Handle test

This ROCr test uses MPI to export and import fabric handles accross different servers to test the Fabric Handle APIs in ROCr.

**The exporter:**
1. Allocates a memory buffer using the VMM APIs.
2. Exports the memory via a fabric handle and sends it to the importer
3. Waits for the importer to finish running a shader
4. Verify the memory allocation to see if it can see the modified buffer.

**The importer:**
1. Receives the fabric handle from the exporter
2. Maps it to a local Virtual Address.
3. Runs a shader on the GPU to verify to copy data from one sub-section within the buffer, to another section.
4. After the GPU shader finishes, verifies the buffer to see if the memory was copied.
5. Sends a notification to the exporter to notify that it is complete.

We need an even number of ranks so that each exporter can partner with an importer. The partner rank is determined by:\
On exporters:
> partner_rank = rank + 1

On importers:
> partner_rank = rank - 1

## Installation
### On all hosts to be tested:
####Install dependencies for mpich
```
sudo apt update && sudo apt install gfortran
```

####Install mpich
Note, the version of mpich that is ships with Ubuntu-24 seems to have problems. You need to install/compile mpich from source.

Download mpich from:
[https://www.mpich.org/downloads/](https://www.mpich.org/downloads/)\
File: [https://www.mpich.org/static/downloads/5.0.0/mpich-5.0.0.tar.gz](https://www.mpich.org/static/downloads/5.0.0/mpich-5.0.0.tar.gz)
```
tar xfz mpich-5.0.0.tar.gz
cd mpich-5.0.0
./configure
make -j 50
sudo make install
```

####Install ROCm


#### Verify hostnames are set on both systems
Make sure /etc/hosts has correct IP addresses for all hosts:

```
cat /etc/hosts
127.0.0.1       localhost
172.27.226.234  host1
10.7.175.79     host2
```

### Compile the test
On the main host, compile the test application:

```
cd <directory>
git clone <this repo>
cd hsa-samples-private/rocr-mpi-test
make
```

On all the other systems, create a ssh mount with the same absolute path as the main system:
Example:

```sshfs -o cache=no,compression=no <main-host>:/<directory>/hsa-samples-private/rocr-mpi-test /<directory>/hsa-samples-private/rocr-mpi-test```

# Usage
Export HWLOC_COMPONENTS to avoid some warnings on some systems

```export HWLOC_COMPONENTS=-gl```

```mpirun -n <number of ranks> -host <host1,host2> ./mpi_rocr_fabric_test```


## Usage scenarios
### Local self-test

Running the application with a single-rank will run a self-test that runs the shader and verifies data on a single system without exporting and importing any fabric handles.

```mpirun -n 1 -host <host1> ./mpi_rocr_fabric_test```




### Run 1 exporter and 1 importer on the same host
When running on a single host, the memory allocation will be created on GPU # with this formula:
> GPU # = rank % num_gpus

```mpirun -n 2 -host <host1> ./mpi_rocr_fabric_test```

- rank 0: Exporter. Memory allocation created on GPU-0
- rank 1: Importer. Memory imported and shader executed on GPU-1


### Run 1 exporter and 1 importer on 2 different hosts
When running on multiple hosts:\
On the exporters, the memory allocation will be created on GPU # with this formula:
> GPU # = (rank/2) % num_gpus

On the importers, the memory mapping and shader will be done on GPU # with this formula:
> GPU # = ((rank - 1)/2) % num_gpus

```mpirun -n 2 -host <host1,host2> ./mpi_rocr_fabric_test```

- rank 0: Exporter. Memory allocation created on host1/GPU-0
- rank 1: Importer. Memory imported on host2/GPU-0. Shader executed host2/GPU-0


### Run multiple importers and exporters per hosts

E.g: Running on multiple GPUs on each host:\
On a system with 4 GPUs\
```mpirun -n 16 -host host1,host2 ./mpi_rocr_fabric_test```

- rank 0: Exporter. Memory allocation created on host1/GPU-0
- rank 1: Importer. Memory imported and shader executed on host2/GPU-0
- rank 2: Exporter. Memory allocation created on host1/GPU-1
- rank 3: Importer. Memory imported and shader executed on host2/GPU-1
- :
- :
- rank 6: Exporter. Memory allocation created on host1/GPU-3
- rank 7: Importer. Memory imported and shader executed on host2/GPU-3
- rank 8: Exporter. Memory allocation created on host1/GPU-0
- rank 9: Importer. Memory imported and shader executed on host2/GPU-0
- :
- :
- rank 14: Exporter. Memory allocation created on host1/GPU-3
- rank 15: Importer. Memory imported and shader executed on host2/GPU-3


E.g: Running on the first GPU on each host:\
```mpirun -n 16 -env ROCR_VISIBLE_DEVICES=0 -host host1,host2 ./mpi_rocr_fabric_test```

- rank 0: Exporter. Memory allocation created on host1/GPU-0
- rank 1: Importer. Memory imported and shader executed on host2/GPU-0
- :
- :
- rank 14: Exporter. Memory allocation created on host1/GPU-0
- rank 15: Importer. Memory imported and shader executed on host2/GPU-0
