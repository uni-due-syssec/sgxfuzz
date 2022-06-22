#!/usr/bin/env bash

set -eo pipefail

ENCLAVE=$(realpath "$1")
TCS=$(realpath "$2")

BASE=$(dirname "$(realpath "$0")")
LAYOUT=$(dirname "$ENCLAVE")/$(basename -s .mem "$ENCLAVE").layout

if [[ $3 == "--no-reload" ]]; then
  echo "No VM reloading..."
  RELOAD="-DNO_VM_RELOAD=1 -DCMAKE_BUILD_TYPE=Debug"
else
  RELOAD="-DNO_VM_RELOAD=0 -DCMAKE_BUILD_TYPE=Debug"
fi

rm -rf "$BASE/build"
mkdir -p "$BASE/build"
pushd "$BASE/build"
cmake "-DENCLAVE_PATH=$ENCLAVE" "-DTCS_PAGE=$(head -1 "$TCS")" "-DENCLAVE_LAYOUT_PATH=$LAYOUT" $RELOAD .. && make fuzz-generic
TARGET=$(realpath fuzz-generic)
popd

cp "$TARGET" "$(basename "$ENCLAVE")".fuzz
