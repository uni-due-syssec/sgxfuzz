
#include <stdio.h>
#include <stdint.h>
#include "kafl_user.h"
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv){
  char buf[1024];

  if(!is_nyx_vcpu()){
    printf("Error: NYX vCPU not found!\n");
    return 0;
  }

  if(argc != 1){
    printf("Usage: <hcat>\n");
    return 1;
  }

  
  while(read(0, buf, sizeof(buf)-1)>0) {
    buf[1023] = 0;
    hprintf("%s", buf);
    memset(buf, 0, 1024);
  }
  return 0;
}