# SGXFuzz: Efficiently Synthesizing Nested Structures for SGX Enclave Fuzzing

*Published at Usenix Security 2022*

SGXFuzz presents a novel approach to fuzz SGX enclaves in a user-space
environment including the synthesis of ECall structures that automatically
synthesizes a nested input structure as expected by the enclaves using a
binary-only approach. The prototype consists of an enclave dumper that
extracts enclaves memory from distribution formats, a fuzzing setup to fuzz
extracted enclave, as well as a series of scripts to perform result
aggregation. The fuzzing setup is the core of SGXFuzz and is built upon the
[kAFL fuzzer](https://github.com/IntelLabs/kAFL) and the [Nyx snapshotting and fuzzing engine](https://nyx-fuzz.com). We extend the existing code of
kAFL to accommodate our structure synthesis in Python. The Nyx fuzzing engine
utilizes the Intel PT CPU extension to get code coverage information but does
not contain any changes for SGXFuzz. Finally, we provide several scripts to
process the crashes found during the fuzzing campaigns as well as the
synthesized structure layouts.


## Description

SGXFuzz consists of the enclave dumper, enclave runner, the fuzzing setup, and
the enclaves evaluated in the paper. The enclave dumper extracts the enclave
memory from enclave distribution formats. This step has to be done only once
per enclave, and we have already performed that step for all enclaves. The
enclave runner uses the previously extracted enclave memory to run the
enclave as a regular user-space process. The runner is a C++ program that
loads the enclave memory, handles the emulation of the context switch that
would usually be performed by the SGX instruction set and performs the
structure allocation for each input. Finally, our fuzzing setup consists of a
front end that generates fuzzing inputs and performs the structure synthesis,
and a back end that executes the target and collects coverage. We use kAFL as
a foundation for our fuzzing front end and add new code to the fuzzer to
perform the structure synthesis. The back end consists of a patched version
of QEMU and KVM to allow the collection of coverage data using the Intel PT
CPU extension. We did not perform any modifications on the fuzzing back end.


## Hardware dependencies

Our fuzzing back end consisting of a modified QEMU and KVM uses the Intel PT
CPU extension to collect coverage data. Thus, an Intel PT-enabled CPU is
required to use our fuzzing setup. However, Intel PT does not work in a
virtualized environment and as such, cannot run in VM. Notice that the
Intel SGX is not required at any point.

## Installation

We include a setup script that should perform the major steps.

* First, disable SGX in the BIOS if supported by the CPU.

* Clone the repository.

* Install required packages:

```
sudo apt install \
  python2 python3 libpixman-1-dev pax-utils bc \
  make cmake gcc g++ pkg-config unzip \
  python3-virtualenv python2-dev python3-dev \
  libglib2.0-dev+ cpio gzip
```

* Then, you can use setup.sh to compile and install the components, or follow
  the steps manually. That is:

  * Initialize the submodules: `git submodule update --init --recursive --depth=1`
  * QEMU-Nyx: https://github.com/nyx-fuzz/QEMU-Nyx#build
  * KVM-Nyx: https://github.com/nyx-fuzz/KVM-Nyx#setup-kvm-nyx-binaries
  * (Virtual) environments for python2 and python3 and install
    * python2: configparser mmh3 lz4 psutil ipdb msgpack inotify
    * python3: six python-dateutil msgpack mmh3 lz4 psutil fastrand inotify pgrep
  * Install zydis (`cd zydis && cmake -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" . && sudo make install && dependencies/zycore && mkdir build && cd build && cmake .. && make && sudo make install `)
  * Prepare the ramfs guest image (`cd packer/linux_initramfs/ && ./pack.sh`)


## Experiment workflow

The experiment workflow includes three main parts: Enclave dumping, Fuzzing,
Result aggregation. 

### Enclave Dumping

First, enclave dumping is used to extract the enclave memory. It is based on
the Linux SGX SDK. By providing the enclave dumper with `enclave.signed.so`,
a memory dump with the name `enclave.signed.so.mem`, a memory layout
`enclave.signed.so.layout`, and the address of the enclave's entry point
(specifically the offset of the TCS) `enclave.signed.so.tcs.txt`.

* Compile is using: `make -C ./enclave-dumper/`
* Run it using: `./enclave-dumper/extract.sh [enclave.signed.so]`

### Fuzzing

To fuzz the previously extracted enclave, several steps are involved. We
bundled all of them together in a script that runs a minimal fuzzing test:

`./run-example.sh`

The script runs the following steps automatically. First, the enclave runner
is compiled using

```
make-enclave-fuzz-target.sh enclave.signed.so.mem \
  enclave.signed.so.tcs.txt
```

The result of the compilation is a `fuzz-generic` binary, which is the
user-space version of the enclave, and a `liblibnyx_dummy.so`, which is
required for the fuzzer. 

In the next step, the fuzzing target is packed into a VM that is executed
using the QEMU-KVM setup. The packer script can be called as follows

```
nyx_packer.py <enclave-runner> <fuzz-folder> m64 \
  --legacy --purge --no_pt_auto_conf_b \
  --fast_reload_mode --delayed_init
```

Finally, the fuzzing can be started using the kAFL fuzzing frontend. The exact
command can be found in the `run_example.sh` script.

### Result Aggregation

**Display synthesized structures:**

```
display-structs.py <path/to/fuzzing-workdir> \
  <ecall_index>
```

The script displays the evolvement of the synthesized structure in a tree
format for each ecall index, with the ecall index being zero-based. The
leaves show the final evolvement of the synthesized structures. Each leave
shows the synthesized structure in a specific format.

Structures are serialized, e.g., `40 2 C8 4 0 C24 7 0`, and read left to
right. This string denotes a structure of **40**\,Bytes, which has two
(**2**) child structures (**C**). The first child is at offset **8** of the
parent and is defined the same way: A size of **4** and zero(**0**) children.
The second child has a size of **7** and also zero children. Further, the
sizes may be annotated with their address (`40:0x7ffff7faafd8`).

If needed, this script shows how to parse and dump these strings:

`kafl/kAFL-Fuzzer/fuzzer/technique/struct_recovery.py`

**Display crashes:**

```
analyze_crashes.py <eval-dir> \
  -0 --np --no-ptr-0x7ff --no-large-diff
```

**Calculate Coverage:**

`calculate-coverage.sh <path/to/fuzzing-workdir>`
