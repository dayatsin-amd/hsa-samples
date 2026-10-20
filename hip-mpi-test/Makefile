EXECS = mpi_hip_fabric_tests

ROCM_DIR ?= /opt/rocm
HIPCC    ?= $(ROCM_DIR)/bin/hipcc
MPICXX   ?= mpicxx

# Extract MPI compiler and linker flags from the MPI wrapper
MPI_CFLAGS  := $(shell $(MPICXX) --showme:compile 2>/dev/null)
MPI_LDFLAGS := $(shell $(MPICXX) --showme:link 2>/dev/null)

CXXFLAGS = -O0 -g -std=c++17 $(MPI_CFLAGS)
LDFLAGS  = $(MPI_LDFLAGS)

all: $(EXECS)

mpi_hip_fabric_tests: mpi_hip_fabric_tests.cc mpi_hip_fabric_helpers.hh
	$(HIPCC) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(EXECS)

.PHONY: all clean
