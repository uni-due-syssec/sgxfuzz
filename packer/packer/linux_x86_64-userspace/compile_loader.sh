mkdir -p bin64/
gcc -O0 -m64 -static -Werror src/loader.c -I../../agents -o bin64/loader