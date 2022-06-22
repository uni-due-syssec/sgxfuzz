#include <string.h>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <errno.h>

#include "sgxerrorprinting.cpp"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

int update = 0;
sgx_launch_token_t token = {0};

int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &update, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

// #######################################################################################################

int main()
{
    int32_t x;

    if (initialize_enclave() < 0) {
        return -1;
    }
    printf("Created enclave: %p\n", global_eid);
    x = fuzz_test("TEST");
    printf("Ret: 0x%x\n", x);
    sgx_destroy_enclave(global_eid);

    return x;
}
