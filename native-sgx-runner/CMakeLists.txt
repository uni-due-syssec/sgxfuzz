cmake_minimum_required(VERSION 3.16)

project(native-sgx-runner)
set(CMAKE_CXX_STANDARD 20)

set(source
		NativeEnclave.cpp
		buffer/GuardedBuffer.cpp
		InputNode.hpp
		)

if (DEFINED ENCLAVE_PATH)
	add_definitions(-DENCLAVE_PATH=${ENCLAVE_PATH})
endif ()
if (DEFINED TCS_PAGE)
	add_definitions(-DTCS_PAGE=${TCS_PAGE})
endif ()
if (DEFINED ENCLAVE_LAYOUT_PATH)
	add_definitions(-DENCLAVE_LAYOUT_PATH=${ENCLAVE_LAYOUT_PATH})
endif ()
if (DEFINED NO_VM_RELOAD)
	add_definitions(-DNO_VM_RELOAD=0${NO_VM_RELOAD})
endif ()

add_library(libnyx_dummy SHARED libnyx.c)
add_executable(fuzz-generic main-generic.cpp ${source})
target_link_libraries(fuzz-generic PRIVATE libnyx_dummy)
