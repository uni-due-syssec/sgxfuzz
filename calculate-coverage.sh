#!/usr/bin/env bash

SGXFUZZ_ROOT=$(dirname "$(realpath "$0")")

WORKDIR=$(realpath "$1")
FUZZ_FOLDER=/tmp/$(basename "$WORKDIR")_fuzz_folder

printf "Using:\t%s\n\t%s\n" "$WORKDIR" "$FUZZ_FOLDER"

PY3=$SGXFUZZ_ROOT/venv-python3/bin/python3

$PY3 /home/jwillbold/kafl/kAFL-Fuzzer/kafl_cov.py \
 -sharedir "$FUZZ_FOLDER" \
 -work_dir "$WORKDIR/sgx_workdir" \
 -input "$WORKDIR/sgx_workdir" \
 -initrd "$SGXFUZZ_ROOT/packer/linux_initramfs/init.cpio.gz" \
 -kernel "$SGXFUZZ_ROOT/packer/linux_initramfs/bzImage-linux-4.15-rc7" \
 -mem 1512 \
 -trace \
 -ip0 0-0
