/*
 * This file is part of Redqueen.
 *
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE

#include <sys/mman.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <time.h>
#include <link.h>
#include <stdbool.h>

#include "../../kafl_user.h"

/* 
    Enable this option to boost targets running in reload mode. 
    Breaks non-reload mode.

     ** Experimental stuff as always! **
*/
//#define FAST_RELOAD_MODE_EXIT

#define ASAN_EXIT_CODE 101
//#define REDIRECT_STDERR_TO_HPRINTF
//#define REDIRECT_STDOUT_TO_HPRINTF

extern uint8_t stdin_mode;
extern char* output_filename;

extern uint32_t memlimit;

int _mlock(void* dst, size_t size) {
    syscall(SYS_mlock, dst, size);
}

int _mlockall(int flags){
    syscall(SYS_mlockall, flags);
}

long int random(void){
    return 0;
}

int rand(void){
    return 0;
}

static inline uint64_t bench_start(void)
{
  unsigned  cycles_low, cycles_high;
  asm volatile( "CPUID\n\t" // serialize
                "RDTSC\n\t" // read clock
                "MOV %%edx, %0\n\t"
                "MOV %%eax, %1\n\t"
                : "=r" (cycles_high), "=r" (cycles_low)
                :: "%rax", "%rbx", "%rcx", "%rdx" );
  return ((uint64_t) cycles_high << 32) | cycles_low;
}

static void debug_time(void){
    time_t timer;
    char buffer[26];
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    hprintf("Time: %s - TSC: %lx\n", buffer, bench_start);
}

void fault_handler(int signo, siginfo_t *info, void *extra) {
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, 1);
}

static void setHandler(void (*handler)(int,siginfo_t *,void *)){
    hprintf("%s\n", __func__);
    struct sigaction action;
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = handler;

    if (sigaction(SIGFPE, &action, NULL) == -1) {
        hprintf("sigfpe: sigaction");
        _exit(1);
    }
    if (sigaction(SIGILL, &action, NULL) == -1) {
        hprintf("sigill: sigaction");
        _exit(1);
    }
    if (sigaction(SIGSEGV, &action, NULL) == -1) {
        hprintf("sigsegv: sigaction");
        _exit(1);
    }
    if (sigaction(SIGBUS, &action, NULL) == -1) {
        hprintf("sigbus: sigaction");
        _exit(1);
    }
    if (sigaction(SIGABRT, &action, NULL) == -1) {
        hprintf("sigabrt: sigaction");
        _exit(1);
    }
    if (sigaction(SIGIOT, &action, NULL) == -1) {
        hprintf("sigiot: sigaction");
        _exit(1);
    }
    if (sigaction(SIGTRAP, &action, NULL) == -1) {
        hprintf("sigiot: sigaction");
        _exit(1);
    }
    if (sigaction(SIGSYS, &action, NULL) == -1) {
        hprintf("sigsys: sigaction");
        _exit(1);
    }
}

#if defined(__x86_64__)

typedef struct address_range_s{
    char* name;
    bool found;
    uint64_t start;
    uint64_t end; 

    uint64_t ip0_a;
    uint64_t ip0_b;

    uint64_t ip1_a;
    uint64_t ip1_b;
} address_range_t;

static int callback(struct dl_phdr_info *info, size_t size, void *data){
    address_range_t* ar = (address_range_t*) data;
    if(ar){
        if(!!strstr(info->dlpi_name, ar->name)){
            char *type;
            int p_type, j;

            for (j = 0; j < info->dlpi_phnum; j++) {
                if(j == 0){
                    ar->start = (uint64_t)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
                    continue;
                }

                if(j == info->dlpi_phnum-1){
                    ar->end = (uint64_t)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr) + info->dlpi_phdr[j].p_memsz;
                    ar->found = true;
                    break;
                }
            }
        }
    }
    return 0;
}

void calc_address_range(address_range_t* ar){

    dl_iterate_phdr(callback, (void*)ar);

    if(ar->found){
        ar->ip0_a = 0x1000UL;
        ar->ip0_b = ar->start-1;

        ar->ip1_a = ar->end;
        ar->ip1_b = 0x7ffffffff000;
    }
}
#endif

#ifdef FAST_RELOAD_MODE_EXIT
void fast_exit(void){
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
}
#endif

int __libc_start_main(int (*main) (int,char **,char **),
              int argc,char **ubp_av,
              void (*init) (void),
              void (*fini)(void),
              void (*rtld_fini)(void),
              void (*stack_end)) {

    int (*original__libc_start_main)(int (*main) (int,char **,char **),
                    int argc,char **ubp_av,
                    void (*init) (void),
                    void (*fini)(void),
                    void (*rtld_fini)(void),
                    void (*stack_end)) = NULL;

    if(stdin_mode){
		hprintf("Using stdin mode\n");
	} else {
        hprintf("file mode (%s)\n", output_filename);
    }
    #if defined(REDIRECT_STDERR_TO_HPRINTF) || defined(REDIRECT_STDOUT_TO_HPRINTF)
    char buf[HPRINTF_MAX_SIZE];
    #endif

    system("rm /tmp/target_executable");

    struct rlimit r;
    int fd, fd2 = 0;
    int pipefd[2];
    int ret = pipe(pipefd);

    #ifdef REDIRECT_STDERR_TO_HPRINTF
    int pipe_stderr_hprintf[2];
    ret = pipe(pipe_stderr_hprintf);
    #endif
    #ifdef REDIRECT_STDOUT_TO_HPRINTF
    int pipe_stdout_hprintf[2];
    ret = pipe(pipe_stdout_hprintf);
    #endif

    struct iovec iov;
    int pid;
    int status=0;
    int res = 0;
    int i;

    r.rlim_max = (rlim_t)(memlimit << 20);
    r.rlim_cur = (rlim_t)(memlimit << 20);

    original__libc_start_main = dlsym(RTLD_NEXT,"__libc_start_main");

    dup2(open("/dev/null", O_WRONLY), STDOUT_FILENO);
    dup2(open("/dev/null", O_WRONLY), STDERR_FILENO);

    if(!stdin_mode){
        dup2(open("/dev/null", O_RDONLY), STDIN_FILENO);
    }
                
    kAFL_payload* payload_buffer = mmap((void*)NULL, PAYLOAD_SIZE, PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    _mlock((void*)payload_buffer, (size_t)PAYLOAD_SIZE);
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);

    kAFL_ranges* range_buffer = mmap((void*)NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(range_buffer, 0xff, 0x1000);
    kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE, (uintptr_t)range_buffer);
 
    for(i = 0; i < 4; i++){
        hprintf("Range %d Enabled: %x\t(%"PRIx64"-%"PRIx64")\n", i, (uint8_t)range_buffer->enabled[i], range_buffer->ip[i], range_buffer->size[i]);
    }

#if defined(__i386__)
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_32);
#elif defined(__x86_64__)
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
#endif

    setrlimit(RLIMIT_AS, &r);

#if defined(__i386__)
#pragma warning("i386 target does not support computing KAFL_RANGE")
#elif defined(__x86_64__)
    address_range_t* ar = malloc(sizeof(address_range_t));
    memset(ar, 0x0, sizeof(address_range_t));
    ar->name = "kafl_user_loader.so";
    calc_address_range(ar);

    if(ar->found){
        hprintf("=> Mapped at:\t0x%016lx-0x%016lx\n\n", ar->start, ar->end);
        hprintf("=> IP0:\t\t0x%016lx-0x%016lx\n", ar->ip0_a, ar->ip0_b);
        hprintf("=> IP1:\t\t0x%016lx-0x%016lx\n", ar->ip1_a, ar->ip1_b);
    }

    uint64_t* ranges = malloc(sizeof(uint64_t)*8);
    memset(ranges, 0x0, sizeof(uint64_t)*8);
    ranges[0] = ar->ip0_a;
    ranges[1] = ar->ip0_b;
    ranges[2] = ar->ip1_a;
    ranges[3] = ar->ip1_b;
    kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uintptr_t)ranges);

    free(ar);
    free(ranges);
#endif

    uint8_t mlock_enabled = 1;


    if(_mlockall(MCL_CURRENT)){
         hprintf("mlockall(MCL_CURRENT) failed!\n");
        kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
    }

    setHandler(fault_handler);
#ifdef FAST_RELOAD_MODE_EXIT
    atexit(fast_exit);
#endif
    while(1){
        pid = fork();

        if(!pid){
            if(mlock_enabled){
                setHandler(fault_handler);
                if(_mlockall(MCL_CURRENT)){
                    hprintf("mlockall(MCL_CURRENT) failed!\n");
                    kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
                }
            }

            if(stdin_mode){
                pipe(pipefd);
            }
            else{
                fd = open(output_filename, O_RDWR | O_CREAT | O_TRUNC);
            }

            kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);

            //debug_time();

            if (stdin_mode){
                if(payload_buffer->size){
                    iov.iov_base = payload_buffer->data;
                    iov.iov_len = payload_buffer->size;

                    ret = vmsplice(pipefd[1], &iov, 1, SPLICE_F_GIFT);
                }
                dup2(pipefd[0],STDIN_FILENO);
                close(pipefd[1]);  
            }
            else{
                write(fd, payload_buffer->data, payload_buffer->size);
            }

            #ifdef REDIRECT_STDERR_TO_HPRINTF
            dup2(pipe_stderr_hprintf[1], STDERR_FILENO);
            close(pipe_stderr_hprintf[0]);
            #endif
            #ifdef REDIRECT_STDOUT_TO_HPRINTF
            dup2(pipe_stdout_hprintf[1], STDOUT_FILENO);
            close(pipe_stdout_hprintf[0]);
            #endif  

            return original__libc_start_main(main,argc,ubp_av, init,fini,rtld_fini,stack_end);
        }
        else if(pid > 0){
            #ifdef REDIRECT_STDERR_TO_HPRINTF
            close(pipe_stderr_hprintf[1]);
            #endif
            #ifdef REDIRECT_STDOUT_TO_HPRINTF
            close(pipe_stdout_hprintf[1]);
            #endif          
            waitpid(pid, &status, WUNTRACED);
            if(WIFSIGNALED(status)){
                kAFL_hypercall(HYPERCALL_KAFL_PANIC, 1);
            } 
            else if (WEXITSTATUS(status) == ASAN_EXIT_CODE) {
                kAFL_hypercall(HYPERCALL_KAFL_KASAN, 1);
            }

            #ifdef REDIRECT_STDERR_TO_HPRINTF
            hprintf("------------STDERR-----------\n");
            while(read(pipe_stderr_hprintf[0], buf, HPRINTF_MAX_SIZE)){
                hprintf("%s", buf);
            }
            hprintf("-----------------------------\n");
            #endif 
            #ifdef REDIRECT_STDOUT_TO_HPRINTF
            hprintf("------------STDDOUT-----------\n");
            while(read(pipe_stdout_hprintf[0], buf, HPRINTF_MAX_SIZE)){
                hprintf("%s", buf);
            }
            hprintf("-----------------------------\n");
            #endif 
         
            kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
            mlock_enabled = 0;



        }
        else{
            hprintf("FORK FAILED ?!\n");
        }
    }
}
