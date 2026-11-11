EXECS=mpi_rocr_fabric_test mpi_rocr_fabric_async_copy_test mpi_rocr_fabric_shootdown_test
#MPICC?=mpicc
MPICC?=mpicxx

#ROCM_DIR=/opt/rocm-6.4.0
ROCM_DIR=../opt/rocm-6.4.0

CXXFLAGS = -I${ROCM_DIR}/include -O0 -ggdb3  -std=c++11
LDFLAGS =-L${ROCM_DIR}/lib -lhsa-runtime64

all: ${EXECS}

mpi_rocr_fabric_test: mpi_rocr_fabric_test.cc
	${MPICC} -o mpi_rocr_fabric_test mpi_rocr_fabric_test.cc ${CXXFLAGS} ${LDFLAGS}

mpi_rocr_fabric_async_copy_test: mpi_rocr_fabric_async_copy_test.cc
	${MPICC} -o mpi_rocr_fabric_async_copy_test mpi_rocr_fabric_async_copy_test.cc ${CXXFLAGS} ${LDFLAGS}

mpi_rocr_fabric_shootdown_test: mpi_rocr_fabric_shootdown_test.cc mpi_rocr_fabric_common.hh
	${MPICC} -o mpi_rocr_fabric_shootdown_test mpi_rocr_fabric_shootdown_test.cc ${CXXFLAGS} ${LDFLAGS}

clean:
	rm ${EXECS}
