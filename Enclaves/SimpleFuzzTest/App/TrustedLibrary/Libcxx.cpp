#include "../App.h"
#include "Enclave_u.h"

int32_t fuzz_test(char* str, int str_len) {
//    int32_t e_ret;
    sgx_status_t ret = fuzz_ecall(global_eid, str, str_len);
    if(ret == SGX_SUCCESS)
        return 0;
    else
        return -1;
}

