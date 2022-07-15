#define _GNU_SOURCE

#include <signal.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <execinfo.h>
#include <stdbool.h>
#include <sys/stat.h> 
#include <stdio.h>

//#include <ucontext.h>
#include "nyx.h"
#include "misc/crash_handler.h"
#include "misc/harness_state.h"
#include "misc/struct_synth_report.h"

static char* log_content = NULL;
static bool ready = false;
char* struct_synth_addrs = NULL;
size_t struct_synth_addrs_len = 0;
char* struct_synth_report = NULL;
//void* decode_stack = NULL;

void handle_asan(void);

static bool file_exists (char *filename) {
  struct stat   buffer;   
  return (stat (filename, &buffer) == 0);
}

static bool check_early_env(void){
    return ("echo $NYX_ASAN_EXECUTABLE | grep TRUE");
}

void init_crash_handling(void){
    //hprintf("======== CALLED: %s\n", __func__);
    if(!log_content){
        log_content = malloc(0x1000);
        memset(log_content, 0x00, 0x1000);
    }
    ready = true;
    config_handler();
}

void set_struct_synth_addrs(const char* addrs, ssize_t len) {
    struct_synth_addrs = (char*) addrs;
    struct_synth_addrs_len = len;

    const size_t addr_fmt_len = 16;
    const size_t struct_synth_report_len = struct_synth_addrs_len + addr_fmt_len + 1;
    struct_synth_report = malloc(struct_synth_report_len);
    memset(struct_synth_report, 0x00, struct_synth_report_len);

    stack_t ss;
    ss.ss_size = 0x10000;
    ss.ss_sp = malloc(0x10000);
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);

    /*
    decode_stack = mmap((void*) 0x330000, 0x100000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    hprintf("FAKE STACK AT: %p\n", decode_stack);
    if (decode_stack == MAP_FAILED) {
        kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0xdec0de);
    } */
}

void report_crashing_addr(ucontext_t* context) {
    const register greg_t ip = context->uc_mcontext.gregs[REG_RIP];
    const register greg_t addr = get_crashing_addr(context->uc_mcontext.gregs);

    sprintf(struct_synth_report, "%llx|%s|%llx", addr, struct_synth_addrs ? struct_synth_addrs : "", ip);
    kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)struct_synth_report);
}

static void fault_handler(int signo, siginfo_t* info, void* extra) {
    ucontext_t* context = (ucontext_t*) extra;
    report_crashing_addr(context);

    //kafl_backtrace(info->si_signo);
    uint64_t reason = 0x8000000000000000ULL | context->uc_mcontext.gregs[REG_RIP] | ((uint64_t) info->si_signo << 47);
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, reason);
}

/*
void fault_handler_asm(int, siginfo_t*, void*);
asm(
"fault_handler_asm:"
    "cmpq $0x430000, %rsp;"
    "jb fault_handler_inner_asm_2;"
    "mov $0x420000, %rsp;"
"fault_handler_inner_asm_2:"
    "jmp fault_handler;"
    "ud2;"
);
*/

static void fault_handler_asan(int signo, siginfo_t *info, void *extra){
    handle_asan();
    ucontext_t *context = (ucontext_t *)extra;
    //kafl_backtrace(info->si_signo);
    uint64_t reason = 0x8000000000000000ULL | context->uc_mcontext.gregs[REG_RIP] | ( (uint64_t)info->si_signo << 47);
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, reason);
}


static void set_handler(void (*handler)(int,siginfo_t *,void *)){
    //hprintf("%s\n", __func__);
    struct sigaction action;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    action.sa_sigaction = handler;

    int (*new_sigaction)(int signum, const struct sigaction *act, struct sigaction *oldact);
    new_sigaction = dlsym(RTLD_NEXT, "sigaction");
        
    if(!get_harness_state()->asan_executable){
        if (new_sigaction(SIGSEGV, &action, NULL) == -1) {
            hprintf("sigsegv: sigaction");
            _exit(1);
        }
        if (new_sigaction(SIGFPE, &action, NULL) == -1) {
            hprintf("sigfpe: sigaction");
            _exit(1);
        }
        if (new_sigaction(SIGBUS, &action, NULL) == -1) {
            hprintf("sigbus: sigaction");
            _exit(1);
        }
    }
    
//    if (new_sigaction(SIGILL, &action, NULL) == -1) {
//        hprintf("sigill: sigaction");
//        _exit(1);
//    }
    
    if (new_sigaction(SIGABRT, &action, NULL) == -1) {
        hprintf("sigabrt: sigaction");
        _exit(1);
    }
    if (new_sigaction(SIGIOT, &action, NULL) == -1) {
        hprintf("sigiot: sigaction");
        _exit(1);
    }
    if (new_sigaction(SIGTRAP, &action, NULL) == -1) {
        hprintf("sigiot: sigaction");
        _exit(1);
    }
    if (new_sigaction(SIGSYS, &action, NULL) == -1) {
        hprintf("sigsys: sigaction");
        _exit(1);
    }
    hprintf("[!] all signal handlers are hooked!\n");
    //kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
}

void config_handler(void){
    if(!get_harness_state()->asan_executable){
        set_handler(fault_handler);
    } 
    else{
        set_handler(fault_handler_asan);
    }
}


/* todo: allow sigaction for SIGSEGV once (allow ASAN to set a sighandler) */ 
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact){
    int (*new_sigaction)(int signum, const struct sigaction *act, struct sigaction *oldact);

    if(ready){
        switch(signum){
            /* forbidden signals */
            case SIGFPE:
//            case SIGILL:
            case SIGBUS:
            case SIGABRT:
            case SIGTRAP:
            case SIGSYS:            
            case SIGSEGV:
                //hprintf("Target attempts to install own SIG: %d handler\n", signum);
                return 0;
            default:
                //hprintf("===> %s: SIG: %d\n", __func__, signum);
                new_sigaction = dlsym(RTLD_NEXT, "sigaction");
                return new_sigaction(signum, act, oldact);
        }
    }
    else{
        //hprintf("===> %s: SIG: %d\n", __func__, signum);
        new_sigaction = dlsym(RTLD_NEXT, "sigaction");
        return new_sigaction(signum, act, oldact);
    }
}

void handle_asan(void){
    char* log_file_path = NULL;
    char* log_content = NULL;

    asprintf(&log_file_path, "/tmp/data.log.%d", getpid());

    FILE* f = fopen(log_file_path, "r");

    if(f){
        log_content = malloc(0x1000);
        memset(log_content, 0x00, 0x1000);
        fread(log_content, 0x1000-1, 1, f);
        fclose(f);
        printf("%s\n", log_content);

        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
    }
}

void __assert(const char *func, const char *file, int line, const char *failedexpr){
        sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: assert: %s %s %d: %s\n", func, file, line, failedexpr);
        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
}

void _abort(void){
        handle_asan();
        sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: abort called: %p\n", __builtin_return_address(0));
        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
        while(1){}
}

void abort(void){
        handle_asan();
        sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: abort called: %p\n", __builtin_return_address(0));
        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
        while(1){}
}

void __abort(void){
        handle_asan();
        sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: abort called: %p\n", __builtin_return_address(0));
        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
        while(1){}
}

void __assert_fail (const char *__assertion, const char *__file, unsigned int __line, const char *__function){
        sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: assert: %s %s %d: %s\n", __function, __file, __line, __assertion);
        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
}

void __assert_perror_fail (int __errnum, const char *__file, unsigned int __line, const char *__function){
    sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: assert: %s %s %d: %d\n", __function, __file, __line, __errnum);
        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
}


#define BT_BUF_SIZE 100

void kafl_backtrace(int signal){

    int fd[2];

    char tmp[512];
    void *buffer[BT_BUF_SIZE];
    int nptrs = 0;
    int j;
    int offset = 0;

    int bytes_read = 0;

    pipe(fd);

    nptrs = backtrace(buffer, BT_BUF_SIZE);
    //hprintf("backtrace() returned %d addresses\n", nptrs);

    
    backtrace_symbols_fd(buffer, nptrs, fd[1]);
    close(fd[1]);
    
    
/*
    char **strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        //perror("backtrace_symbols");
        //hprintf("backtrace_symbols failed!\n");
        return;
        //exit(EXIT_FAILURE);
    }
*/    

    offset += sprintf(log_content+offset, "HYPERCALL_KAFL_PANIC_EXTENDED: %s - addresses: %d (signal:%d)\n", __func__, nptrs, signal);

    bytes_read = read(fd[0], tmp, 511);
    //hprintf("bytes_read1: %d\n", bytes_read);
    while(bytes_read != 0){
        tmp[bytes_read] = 0;
        offset += sprintf(log_content+offset, "%s\n", tmp);
        bytes_read = read(fd[0], tmp, 511);
        //hprintf("bytes_read2: %d\n", bytes_read);
    }
    
    /*
    for (j = 0; j < nptrs; j++){
        offset += sprintf(log_content+offset, "%s\n", strings[j]);
        //hprintf("%s\n", strings[j]);
    }
    */

    kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);

    //free(strings);
}


void fail(void){
    void* a= NULL;
    *((char*)a) = 'a';
}
