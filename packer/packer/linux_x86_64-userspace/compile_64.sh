mkdir -p bin64/

if [ "$LEGACY_MODE" = "ON" ]
then
  # old kAFL mode shared library
  gcc -shared -O0 -m64 -Werror -DLEGACY_MODE -fPIC src/ld_preload_fuzz.c src/misc/crash_handler.c src/misc/harness_state.c src/misc/struct_synth_report.c src/netfuzz/syscalls.c -I../../agents -o bin64/ld_preload_fuzz_legacy.so -ldl -lZydis -Isrc
else
  # latest and greatest nyx shared library

  if [ "$NET_FUZZ" = "ON" ]
  then

    MODE="${UDP_MODE} ${CLIENT_MODE} ${DEBUG_MODE} ${STDOUT_STDERR_DEBUG}"
    echo "MODES => $MODE"

    clang -shared -g -O0 -m64 -Werror $MODE -fPIC src/ld_preload_fuzz.c src/misc/crash_handler.c src/misc/harness_state.c src/netfuzz/inject.c src/netfuzz/syscalls.c src/netfuzz/socket_cache.c -I../../agents -DNET_FUZZ -I$NYX_SPEC_FOLDER -o bin64/ld_preload_fuzz.so -ldl -Isrc

    #echo "NET FUZZ! FUCK YEAH!"
    #if [ "$UDP_MODE" = "ON" ]
    #then
    #  clang -shared -g -O0  -m64 -Werror -DUDP_MODE -fPIC src/ld_preload_fuzz.c src/misc/crash_handler.c src/misc/harness_state.c src/netfuzz/inject.c src/netfuzz/syscalls.c src/netfuzz/socket_cache.c -I../../agents -DNET_FUZZ -I$NYX_SPEC_FOLDER -o bin64/ld_preload_fuzz.so -ldl -Isrc
    #else
    #
    #  if [ "$CLIENT_MODE" = "ON" ]
    #  then
    #    clang -shared -g -O0  -m64 -Werror -DCLIENT_MODE -fPIC src/ld_preload_fuzz.c src/misc/crash_handler.c src/misc/harness_state.c src/netfuzz/inject.c src/netfuzz/syscalls.c src/netfuzz/socket_cache.c -I../../agents -DNET_FUZZ -I$NYX_SPEC_FOLDER -o bin64/ld_preload_fuzz.so -ldl -Isrc
    #  else
    #    clang -shared -g -O0  -m64 -Werror -fPIC src/ld_preload_fuzz.c src/misc/crash_handler.c src/misc/harness_state.c src/netfuzz/inject.c src/netfuzz/syscalls.c src/netfuzz/socket_cache.c -I../../agents -DNET_FUZZ -I$NYX_SPEC_FOLDER -o bin64/ld_preload_fuzz.so -ldl -Isrc
    #  fi
    #fi
  else
    echo "YO"
    gcc -shared -O0 -m64 -Werror -fPIC src/ld_preload_fuzz.c src/misc/crash_handler.c src/netfuzz/syscalls.c src/misc/harness_state.c -I../../agents  -I$NYX_SPEC_FOLDER -o bin64/ld_preload_fuzz.so -ldl -Isrc
  fi
fi

gcc -m64  src/libnyx.c -o bin64/libnyx.so -shared -fPIC -Wall -std=gnu11 -Wl,-soname,libnyx.so
gcc -O0 -m64 -Werror src/htools/habort.c -I../../agents -o bin64/habort
gcc -O0 -m64 -Werror src/htools/hcat.c -I../../agents -o bin64/hcat
gcc -O0 -m64 -Werror src/htools/hget.c -I../../agents -o bin64/hget
gcc -O0 -m64 -Werror src/htools/hpush.c -I../../agents -o bin64/hpush

gcc -O0 -m64 -static -Werror src/loader.c -I../../agents -o bin64/loader
