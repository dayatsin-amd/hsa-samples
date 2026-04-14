SOURCES = memory_fill.cpp
OBJECTS = $(SOURCES:.cpp=.o)

EXECUTABLE=./memory_fill

.PHONY: test

all: $(EXECUTABLE) 

CXXFLAGS = -I/opt/rocm/include -O0 -g -std=c++11
LDFLAGS =-L/opt/rocm/lib -lhsa-runtime64 
CXX=g++

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

clean:
	rm -f $(EXECUTABLE)
	rm -f $(OBJECTS)
