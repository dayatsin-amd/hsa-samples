# ROCr/HSA MPI based Fabric Handle test

This ROCr test uses MPI to export and import fabric handles accross different servers to test the Fabric Handle APIs in ROCr.

This directory contains three tests:
- `mpi_rocr_fabric_test`: exports a fabric handle and runs a shader on the importing GPU to copy data within the buffer (described below).
- `mpi_rocr_fabric_async_copy_test`: exports a fabric handle and uses an asynchronous memory copy on the importing GPU instead of a shader (see [mpi_rocr_fabric_async_copy_test](#mpi_rocr_fabric_async_copy_test)).
- `mpi_rocr_fabric_shootdown_test`: orders the exporter's release before the importer's, so the remote TLB shootdown condition is created rather than raced (see [Remote TLB shootdown ordering test](#remote-tlb-shootdown-ordering-test)).

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

## mpi_rocr_fabric_async_copy_test

This test uses MPI to export and import fabric handles across servers, like `mpi_rocr_fabric_test`, but the importer copies data with an asynchronous copy (`hsa_amd_memory_async_copy`) instead of running a shader.

**The exporter:**
1. Allocates a memory buffer of the requested size using the VMM APIs and zeroes it.
2. Initializes the first half of the buffer with a byte pattern (0, 1, 2, ...).
3. Exports the memory via a fabric handle and sends the size and handle to the importer.
4. Waits for the importer to finish the copy.
5. Verifies that the second half of the buffer matches the first half.

**The importer:**
1. Receives the size and fabric handle from the exporter.
2. Imports the handle and maps it to a local Virtual Address.
3. Copies the first half of the buffer to the second half with an asynchronous copy and waits for its completion signal.
4. Sends a completion status to the exporter.

The partner rank and GPU selection follow the same rules as `mpi_rocr_fabric_test`, so an even number of ranks is required.

### Build

`make` builds both `mpi_rocr_fabric_test` and `mpi_rocr_fabric_async_copy_test`. To build only this test:

```
make mpi_rocr_fabric_async_copy_test
```

### Usage

```
mpirun -n <number of ranks> -host <host1,host2> ./mpi_rocr_fabric_async_copy_test [size]
```

- `size` is the total buffer size in bytes. It accepts an optional `K`, `M`, or `G` suffix (for example `4K`, `1M`, `2G`). The copy transfers half of the buffer, so `1M` copies 512K.
- If `size` is omitted, the test runs a sweep from 4K to 512M.
- Set `WAIT_FOR_GDB=1` to make the importer wait for a debugger to attach before it starts the copy.

Each run prints `Data verification size:<size> PASS` or `FAIL` on the exporter.

### Usage scenarios

E.g: Run a single 1M buffer with 1 exporter and 1 importer on the same host:
```mpirun -n 2 -host <host1> ./mpi_rocr_fabric_async_copy_test 1M```

- rank 0: Exporter. Memory allocation created on GPU-0
- rank 1: Importer. Memory imported and async copy executed on GPU-1

E.g: Run a 1M buffer with 1 exporter and 1 importer on 2 different hosts:
```mpirun -n 2 -host <host1,host2> ./mpi_rocr_fabric_async_copy_test 1M```

- rank 0: Exporter. Memory allocation created on host1/GPU-0
- rank 1: Importer. Memory imported and async copy executed on host2/GPU-0
## Remote TLB shootdown ordering test

`mpi_rocr_fabric_shootdown_test` covers a case the test above does not.

The driver sends the remote TLB shootdown from the **exporter** side, when the
exported allocation is cleaned up, and only while the set of live importers is
non-empty. The test above does not order the two teardowns: the importer sends
its result and immediately unmaps, while the exporter verifies a whole buffer
before it unmaps, so in practice the importer tends to release first. When it
does, the exporter's cleanup finds no importer to notify and sends nothing.
Whether a shootdown is produced therefore depends on how that race lands.

This test removes the race with an explicit handshake. The importer maps, runs
a shader to populate its translations, reports ready, and then **blocks** until
the exporter says it has released. The exporter's release is guaranteed to
happen while a remote importer is still mapped.

```
mpirun -n 2 -host <hostA>,<hostB> ./mpi_rocr_fabric_shootdown_test
```

Two hosts are required. With both ranks on one host the import is satisfied
locally, no remote importer is recorded, and no shootdown can be produced no
matter how the teardown is ordered. The test detects this and exits with
`-EOPNOTSUPP` rather than reporting a pass that proves nothing.

### Reading the result

A clean exit means the **condition** was created, not that the shootdown
happened. There is no userspace signal for it. Confirm on the exporter host:

```
sudo dmesg -C
mpirun -n 2 -host <hostA>,<hostB> ./mpi_rocr_fabric_shootdown_test
sudo dmesg | grep -i shootdown
```

Driver debug output may need to be enabled first, for example via dynamic debug
on the relevant amdgpu source file. If the running driver does not send remote
shootdowns, nothing will appear. That is an observation about the driver, not a
failure of this test - the test's job is to create the condition.

### `--probe-after-release`

Optional. The importer touches the imported memory *after* the exporter has
released it. If the shootdown did not happen the importer reads through a stale
translation into freed memory; if it did happen the access faults. Both outcomes
are informative and neither is a clean run, so this is a debugging aid. Do not
enable it in CI.
