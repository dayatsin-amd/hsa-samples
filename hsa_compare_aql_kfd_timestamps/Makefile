EXECS=hsa_ts_check
CXX=c++

ROCM_DIR=/opt/rocm

CXXFLAGS = -I${ROCM_DIR}/include -O0 -g -std=c++11
LDFLAGS =-L${ROCM_DIR}/lib -lhsa-runtime64

all: ${EXECS}

hsa_ts_check: hsa_ts_check.cc
	${CXX} -o hsa_ts_check hsa_ts_check.cc ${CXXFLAGS} ${LDFLAGS}

clean:
	rm ${EXECS}
