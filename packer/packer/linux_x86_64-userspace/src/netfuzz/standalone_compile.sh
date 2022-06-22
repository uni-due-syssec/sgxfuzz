gcc -shared -fPIC -o inject.so inject.c syscalls.c socket_cache.c -ldl
gcc -shared -fPIC -o inject_debug.so inject.c syscalls.c socket_cache.c -ldl -DDEBUG_MODE
