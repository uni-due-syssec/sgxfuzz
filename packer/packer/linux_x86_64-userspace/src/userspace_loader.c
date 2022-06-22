/*

Copyright (C) 2018 Sergej Schumilo

This file is part of QEMU-PT (kAFL / Redqueen).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#define _GNU_SOURCE 

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>

#include "kafl_user.h"

extern uint8_t extra_args;
extern char* args[];

extern uint8_t _binary_ld_preload_target_start;
extern uint8_t _binary_ld_preload_target_end;
extern uint8_t _binary_ld_preload_target_size;

extern uint8_t _binary_target_start;
extern uint8_t _binary_target_end;
extern uint8_t _binary_target_size;

extern uint32_t libraries;
extern uint8_t* library_address_start[];
extern uint8_t* library_address_end[];
extern char* library_name[];

extern uint8_t asan_enabled;
extern char* libasan_name;

extern bool delayed_init;

extern uint8_t _binary_extra_data_start;
extern uint8_t _binary_extra_data_end;
extern uint8_t _binary_extra_data_size;

extern char* extra_data_name;

#define TARGET_US_LD_FILE  "/tmp/kafl_user_loader.so"
#define TARGET_US_FILE "/tmp/target_executable"

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) - 1)
#endif

static inline void panic(void){
	kAFL_hypercall(HYPERCALL_KAFL_PANIC, (uintptr_t)0x1);
	while(1){}; /* halt */
}

static void show_dmesg(void){
  hprintf("%s\n");
  //struct stat buf;  
  char buffer[513];
  system("dmesg | grep segfault > /tmp/crash_log.txt");

  

  int dmesg_file = open("/tmp/crash_log.txt", O_RDONLY);

  //fstat(dmesg_file, &buf);
  //int size = buf.st_size;

  while(read(dmesg_file, buffer, 512) > 0){
    buffer[512] = 0;
    hprintf("DMESG: %s\n", buffer);
  }
  close(dmesg_file);
}

static inline void load_programm(void){

  char* newenviron[6];
  if (asan_enabled) {
    newenviron[0] = "LD_LIBRARY_PATH=/tmp/";
    newenviron[1] = "LD_BIND_NOW=1";
    if (strlen(libasan_name) != 0){
    	asprintf(&(newenviron[2]), "LD_PRELOAD=/tmp/%s:/tmp/kafl_user_loader.so", libasan_name);
    	hprintf("newenviron[2]): %s\n", newenviron[2]);
    }
    else {
    	//newenviron[2] = "LD_PRELOAD=/tmp/libasan.so.2:/tmp/kafl_user_loader.so";	/* fix me */
    	hprintf("(strlen(libasan_name) == 0) <= FIX ME\n");
    	panic();
    }
    newenviron[3] = "ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:exitcode=101"; /* forget about those memleaks :P ... */
  } else {
    newenviron[0] = "LD_LIBRARY_PATH=/tmp/";
    newenviron[1] = "LD_BIND_NOW=1";
    newenviron[2] = "LD_PRELOAD=/tmp/kafl_user_loader.so";
    newenviron[3] = "ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:exitcode=101"; /* forget about those memleaks :P ... */

  }
  if(delayed_init){
    hprintf("Let's enable delayed_init mode \n!");
    newenviron[4] = "DELAYED_NYX_FUZZER_INIT=ON";
    newenviron[5] = NULL;
  }
  else{
    newenviron[4] = NULL;
  }

  hprintf("ENV: %s\n", newenviron[0]);

  chdir("/tmp");
  int payload_file = open("target_executable", O_RDONLY);
  fexecve(payload_file, args, newenviron);
}

void child(void){
  load_programm();
  hprintf("Fail: %s\n", strerror(errno));
}

static void copy_binary(char* name, char* path, void* start_address, void* end_address){
  int payload_file;
  char* full_path;
  hprintf("<<%s>>\n", name);
  uint64_t size = end_address-start_address;
  hprintf("[!] binary (%s) is %d bytes in size...\n", name, size);
  asprintf(&full_path, "%s/%s", path, name);
  hprintf("[!] writing to \"%s\"\n", full_path);
  payload_file = open(full_path, O_RDWR | O_CREAT | O_SYNC, 0777);
  write(payload_file, (void*)start_address, size);
  hprintf("[*] write: %s\n", strerror(errno));
  close(payload_file);
  hprintf("[*] close: %s\n\n", strerror(errno));
}

void parent(int pid){
  int status=0;
  int waitoptions = 0;
  int res = 0;
  waitpid(pid, &status, waitoptions);

  printf("OOPS?!\n");


  show_dmesg();

  /* something went wrong ... alert the hypervisor / fuzzer */
  panic();
}

int main(int argc, char** argv){
  char va_space_result;
  int pid, fd;

  system("rm /loader");
  system("rm /tmp/target");

  /* check if uid == 0 */
  if(getuid()){
    hprintf("Oops...no root creds?\n");
    return 1;
  }
  hprintf("[*] getuid() == 0\n");

    /* disable ASLR */
  hprintf("[!] disabling ASLR...\n");
  fd = open("/proc/sys/kernel/randomize_va_space", O_WRONLY);
  write(fd, "0", 1);
  close(fd);

  fd = open("/proc/sys/kernel/randomize_va_space", O_RDONLY);
  read(fd, &va_space_result, 1);
  close(fd);
  hprintf("[*] /proc/sys/kernel/randomize_va_space: %c\n\n", va_space_result);

  copy_binary("kafl_user_loader.so", "/tmp", (void*)&_binary_ld_preload_target_start, (void*)&_binary_ld_preload_target_end);
  copy_binary("target_executable", "/tmp", (void*)&_binary_target_start, (void*)&_binary_target_end);

  hprintf("Libraries: %d\n", libraries);
  for(uint32_t i = 0; i < libraries; i++){
  	hprintf("%s\n", library_name[i]);
  	copy_binary(library_name[i], "/tmp", (void*)library_address_start[i], (void*)library_address_end[i]);
  }

  if(extra_data_name){
    copy_binary(extra_data_name, "/tmp", (void*)&_binary_extra_data_start, (void*)&_binary_extra_data_end);
  }

  printf("Done!\n");

  pid = fork();

  if(!pid){
    child();
  }
  else if(pid > 0){
    parent(pid);
  }
  else {
    hprintf("Oops...fork failed?!\n");
    return 1;
  }

  return 0;
}
