mkdir -p bin32/

if [ "$LEGACY_MODE" = "ON" ]
then
  # old kAFL mode shared library
  gcc -shared -O0 -m32 -Werror -DLEGACY_MODE -fPIC src/ld_preload_fuzz.c -I../../agents  -I$NYX_SPEC_FOLDER -o bin32/ld_preload_fuzz_legacy.so -ldl -Isrc
else
  # latest and greatest nyx shared library
  gcc -shared -O0 -m32 -Werror -fPIC src/ld_preload_fuzz.c -I../../agents  -I$NYX_SPEC_FOLDER -o bin32/ld_preload_fuzz.so -ldl -Isrc
fi

gcc -m32  src/libnyx.c -o bin32/libnyx.so -shared -fPIC -Wall -std=gnu11 -Wl,-soname,libnyx.so
gcc -O0 -m32 -Werror src/htools/habort.c -I../../agents -o bin32/habort
gcc -O0 -m32 -Werror src/htools/hcat.c -I../../agents -o bin32/hcat
gcc -O0 -m32 -Werror src/htools/hget.c -I../../agents -o bin32/hget

