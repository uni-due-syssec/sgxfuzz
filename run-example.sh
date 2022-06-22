#!/bin/bash

set -ex

SGXFUZZ_ROOT=$(dirname "$(realpath "$0")")
ENCLAVE_PATH="$SGXFUZZ_ROOT/Enclaves/SimpleFuzzTest"
FUZZ_FOLDER=/tmp/sgxfuzz-fuzz-folder
FUZZ_WORKDIR=/tmp/sgxfuzz-workdir

if [[ ! -d "$SGXFUZZ_ROOT/native-sgx-runner" ]]; then
	echo "Invalid execution directory"
	exit 1
fi

if [[ -r "$SGXFUZZ_ROOT/kvm-nyx-release/kvm-intel.ko" ]]; then
	sudo rmmod kvm_intel || true
	sudo rmmod kvm || true
	sudo insmod "$SGXFUZZ_ROOT/kvm-nyx-release/kvm.ko" || true
	sudo insmod "$SGXFUZZ_ROOT/kvm-nyx-release/kvm-intel.ko" || true
	sudo chmod a+rw /dev/kvm
fi


# Build the enclave runner
"$SGXFUZZ_ROOT/native-sgx-runner/make-enclave-fuzz-target.sh" "$ENCLAVE_PATH/enclave.signed.so.mem" "$ENCLAVE_PATH/enclave.signed.so.tcs.txt"

cp "$SGXFUZZ_ROOT/native-sgx-runner/build/liblibnyx_dummy.so" ./

mkdir -p "$FUZZ_FOLDER"

PY2=$(realpath venv-python2/bin/python2)
PY3=$(realpath venv-python3/bin/python3)


# Pack the target
LD_LIBRARY_PATH=. $PY2 "$SGXFUZZ_ROOT/packer/packer/nyx_packer.py" enclave.signed.so.mem.fuzz "$FUZZ_FOLDER" \
	    m64 --legacy --purge --no_pt_auto_conf_b --fast_reload_mode --delayed_init | tee /dev/tty | grep -qv ERROR

# Start fuzzing
$PY3 "$SGXFUZZ_ROOT/kafl/kAFL-Fuzzer/kafl_fuzz.py" \
	-sharedir "$FUZZ_FOLDER" \
	-work_dir "$FUZZ_WORKDIR" \
	-initrd "$SGXFUZZ_ROOT/packer/linux_initramfs/init.cpio.gz" \
	-kernel "$SGXFUZZ_ROOT/packer/linux_initramfs/bzImage-linux-4.15-rc7" \
	-seed_dir "$SGXFUZZ_ROOT/seeds" \
	--purge -funky \
	-mem 512 -p 8 -redqueen -redq_do_simple -struct_size_havoc \
	|& tee fuzzer.log
