#!/usr/bin/env bash

set -e

SGXFUZZ_ROOT=$(dirname "$(realpath "$0")")

FEATURES=(
    "-struct_size_havoc"

    "-no_struct_ptr_loc_havoc -no_struct_recovery -no_struct_size_detection"
    "-no_struct_ptr_loc_havoc -no_struct_size_detection"
    "-no_struct_ptr_loc_havoc"
    "-no_struct_ptr_loc_havoc -struct_size_havoc"
)

if [[ " $*" == *" -h"* ]]; then
    echo "$(basename "$0") <run-name> <enclave.mem> [ablation id]"
    for (( i = 0; i < ${#FEATURES[@]}; i++ )); do
        echo "    $i: ${FEATURES[$i]}"
    done
    exit 0
fi

# eval name
NAME=$1
# enclave memory dump
ENCLAVE=$(realpath "$2")
BASE=$(realpath ./)

for t in "$ENCLAVE.tcs.txt" \
         "$(dirname "$ENCLAVE")/$(basename -s .mem "$ENCLAVE").tcs.txt" \
         "$(dirname "$ENCLAVE")/tcs.txt"; do
	if [[ -r "$t" ]]; then
		tcs=$(realpath "$t")
		break
	fi
done
if [[ ! -r "$tcs" ]]; then
	echo "TCS not found"
	exit 1
fi
echo "Using TCS: $tcs"

TYPE=${3:-0}
FEATURE=${FEATURES[$TYPE]}
if [[ -z $FEATURE ]]; then
    echo "Invalid Type: $TYPE"
    exit 1
fi
echo "Using Type $TYPE ($FEATURE)"

count=0
evaldir="$BASE/$NAME-T$TYPE-$(date +%F)"
while [[ -e $evaldir ]]; do
	count=$((count+1))
	evaldir="$BASE/$NAME-T$TYPE-$(date +%F)_$count"
done

mkdir -p "$evaldir/sgx_workdir"
cp -r seeds/ "$evaldir/"
cd "$evaldir"

"$SGXFUZZ_ROOT/native-sgx-runner/make-enclave-fuzz-target.sh" "$ENCLAVE" "$tcs" --no-reload
mv "$(basename "$ENCLAVE").fuzz" "$(basename "$ENCLAVE").fuzz-noreload"
ln -rs "$(basename "$ENCLAVE").fuzz-noreload" fuzz-generic

"$SGXFUZZ_ROOT/native-sgx-runner/make-enclave-fuzz-target.sh" "$ENCLAVE" "$tcs"
fuzz_target=$(basename "$ENCLAVE").fuzz

cp "$SGXFUZZ_ROOT/native-sgx-runner/build/liblibnyx_dummy.so" ./

args=""
if [[ -r "$(dirname "$ENCLAVE")/init.raw" ]]; then
    cp "$(dirname "$ENCLAVE")/init.raw" ./
    args="-args init.raw"
fi

share_dir=/tmp/$(basename $evaldir)_fuzz_folder

PY2=$(realpath "$SGXFUZZ_ROOT/venv-python2/bin/python2")
PY3=$(realpath "$SGXFUZZ_ROOT/venv-python3/bin/python3")

cat > pack.sh <<EOF
#!/usr/bin/env bash
mkdir -p "$share_dir"
LD_LIBRARY_PATH=. \\
 "$PY2" "$(realpath "$SGXFUZZ_ROOT/packer/packer/nyx_packer.py")" \\
 "$fuzz_target" \\
 "$share_dir" \\
 m64 --legacy --purge --no_pt_auto_conf_b --fast_reload_mode \\
 --delayed_init \\
 $args
EOF

cat > fuzz.sh <<EOF
#!/usr/bin/env bash

# -struct_size_havoc
# -no_struct_recovery
# -no_struct_ptr_loc_havoc
# -no_struct_size_detection

"$PY3" "$(realpath "$SGXFUZZ_ROOT/kafl/kAFL-Fuzzer/kafl_fuzz.py")" \\
 -sharedir "$share_dir" \\
 -work_dir "$evaldir/sgx_workdir" \\
 -initrd "$(realpath "$SGXFUZZ_ROOT/packer/linux_initramfs/init.cpio.gz")" \\
 -kernel "$(realpath "$SGXFUZZ_ROOT/packer/linux_initramfs/bzImage-linux-4.15-rc7")" \\
 -seed_dir "$evaldir/seeds/" \\
 --purge \\
 -R \\
 -mem 512 \\
 -funky \\
 -p 40 \\
 -redqueen -redq_do_simple \\
 $FEATURE \\
 -abort_time 24 \\
 |& tee fuzzer.log
EOF

chmod +x pack.sh fuzz.sh
