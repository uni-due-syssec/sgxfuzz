
#include <stdio.h>
#include <stdint.h>
#include "nyx.h"
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>


static inline uint64_t get_address(char* identifier)
{
    FILE * fp;
    char * line = NULL;
    ssize_t read;
    ssize_t len;
    char *tmp;
    uint64_t address = 0x0;
    uint8_t identifier_len = strlen(identifier);

    fp = fopen("/proc/kallsyms", "r");
    if (fp == NULL){
        return address;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        if(strlen(line) > identifier_len && !strcmp(line + strlen(line) - identifier_len, identifier)){
                address = strtoull(strtok(line, " "), NULL, 16);
                break;
        }
    }

    fclose(fp);
    if (line){
        free(line);
    }
    return address;
}


bool download_file(const char* filename, const char* dst){
  void* stream_data = mmap((void*)NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
 
  FILE* f = NULL;

  uint64_t bytes = 0;
  uint64_t total = 0;

  do{
    strcpy(stream_data, filename);
    bytes = kAFL_hypercall(HYPERCALL_KAFL_REQ_STREAM_DATA, (uint64_t)stream_data);

    if(bytes == 0xFFFFFFFFFFFFFFFFUL){
      printf("HYPERVISOR: ERROR\n");
      return false;
    }

    if(f == NULL){
      f = fopen(dst, "w+");
    }

      fwrite(stream_data, 1, bytes, f);

      total += bytes;

    } while(bytes);

    printf("%ld bytes received from hypervisor! (%s)\n", total, filename);

    if(f){
      fclose(f);
      return true;
  }
  return false;
}

int main(int argc, char** argv){

	uint64_t panic_handler = 0x0;
	uint64_t kasan_handler = 0x0;

  if(!is_nyx_vcpu()){
    printf("Error: NYX vCPU not found!\n");
    return 0;
  }
  if(argc == 1){
    

    panic_handler = get_address("T panic\n");
    printf("Kernel Panic Handler Address:\t%lx\n", panic_handler);

    kasan_handler = get_address("t kasan_report_error\n");
    if (kasan_handler){
      printf("Kernel KASAN Handler Address:\t%lx\n", kasan_handler);
    }

	  kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);


    if(!download_file("hget", "hget")){
      hprintf("Error: Can't get file 'mget'\n");
      //kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
      kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
    }

    if(!download_file("fuzz.sh", "fuzz.sh")){
      hprintf("Error: Can't get file 'fuzz.sh'\n");
      //kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
      kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
    }

    /* initial fuzzer handshake ... obsolete shit */
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    /* submit panic address */
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_handler);
    /* submit KASan address */
    if (kasan_handler){
      kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_KASAN, kasan_handler);
    }

    system("chmod +x fuzz.sh");
    system("./fuzz.sh");
    while(true){}
  }
  printf("Usage: <loader>\n");
  return 0;
}