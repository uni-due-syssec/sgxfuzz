FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install -y git build-essential python2 python3 pkg-config libgtk-3-dev flex bison

# Install capstone v4 for libxdc
#WORKDIR /build
#RUN git clone https://github.com/aquynh/capstone.git
#WORKDIR /build/capstone
#RUN git checkout v4
#RUN make && make install

# Install libxdc
#WORKDIR /build
#RUN git clone https://github.com/nyx-fuzz/libxdc.git
#WORKDIR /build/libxdc
#RUN make install

WORKDIR /build
RUN git clone https://github.com/nyx-fuzz/QEMU-Nyx.git
WORKDIR /build/QEMU-Nyx
RUN ./compile_qemu_nyx.sh lto

WORKDIR /build
RUN git clone --depth 1 --branch kvm-nyx-5.10.73 git@github.com:nyx-fuzz/kvm-nyx.git
WORKDIR kvm-nyx
RUN sh compile_kvm_nyx_standalone.sh



