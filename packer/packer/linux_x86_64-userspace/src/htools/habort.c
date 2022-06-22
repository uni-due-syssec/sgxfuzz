
#include <stdio.h>
#include <stdint.h>
#include "kafl_user.h"
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv){
  char buf[256];

  if(!is_nyx_vcpu()){
    printf("Error: NYX vCPU not found!\n");
    return 0;
  }

  if(argc != 1){
    printf("Usage: <habort>\n");
    return 1;
  }

  kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, (uint64_t)"FUCK! SOMETHING WENT WRONG -> ABORT!");

  return 0;
}