#include "../Enclave.h"
#include "Enclave_t.h"

void fuzz_ecall(char* buf, int str_len) {
    if(buf[0] == 'F') {
        if(buf[1] == 'U') {
            if(buf[2] == 'Z') {
                if(buf[3] == 'Z') {
                    *(int*)0 = 0;
                }
            }
        }
    }
}
