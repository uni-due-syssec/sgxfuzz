#!/usr/bin/env bash

BASE="$(dirname $0)"
SIGNTOOL="$BASE/sgx_sign"

enclave=$1
shift
out=extract.out
dump=extract.dump

if ! [[ -f $enclave && -r $enclave ]]; then
    echo "ERROR: Cannot open $enclave!"
    exit 1
fi

for f in "$out" "$dump" "$dump.mem" "$dump.layout"; do
    if [[ -e $f ]]; then
        echo "ERROR: '$f' exists"
        exit 1
    fi
done

echo "Running" "$($SIGNTOOL -version |& grep -oP "version \S+")"
echo "Enclave:" "$enclave"
echo "build with:" "$(strings "$enclave" | grep SGX_TSTDC_VERSION)"
echo

echo "--- SGX SIGN ---"
$SIGNTOOL gendata -enclave "$enclave" -out "$out" "$@" | grep -vF '<' > "$dump" || { rm -f -- "$dump"; exit 1; }
echo "--- SGX SIGN END ---"
rm -f -- "$out"

python "$BASE/DumpReader.py" "$dump" | tee "$enclave.tcs.txt"
mv "$dump" "$enclave.dump"

mv "$dump.mem" "$enclave.mem"
mv "$dump.layout" "$enclave.layout"
