#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <system_error>
#include <csignal>

extern "C" {
#include "../packer/agents/nyx.h"
#include "libnyx.h"
}

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x10000
#endif

#include "NativeEnclave.h"

NativeEnclave::NativeEnclave() {
    fakestack = static_cast<uint8_t*>(
        mmap(nullptr, STACK_SIZE,
             PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0));
    assert(fakestack != MAP_FAILED);
}

NativeEnclave::NativeEnclave(const char* dump, void* base_address) : NativeEnclave() {
    load_enclave_dump(base_address, dump);
}

NativeEnclave::NativeEnclave(void* enc_base, uint64_t enc_size) : NativeEnclave() {
    enclave_base = (uint64_t) enc_base;
    enclave_size = enc_size;
}

NativeEnclave::~NativeEnclave() {
    fakestack = nullptr;
    munmap((void*) enclave_base, enclave_size);
    enclave_base = 0;
}

void NativeEnclave::load_enclave_dump(void* address, const char* file_path) {
    int fd;
    struct stat sb{};

    fd = ::open(file_path, O_RDONLY);
    if (fd == -1)
        throw std::system_error();
    if (fstat(fd, &sb) == -1)
        throw std::system_error();

    // TODO: exec needed?
    void* map_addr =
        ::mmap(address, sb.st_size,
               PROT_READ | PROT_WRITE | PROT_EXEC, // NOLINT(hicpp-signed-bitwise)
               MAP_PRIVATE | MAP_FIXED_NOREPLACE, // NOLINT(hicpp-signed-bitwise)
               fd, 0);
    if (map_addr == MAP_FAILED)
        throw std::system_error(errno, std::system_category());
    if (map_addr != address)
        throw std::logic_error("Unexpected mmap address");

    enclave_base = (uint64_t) map_addr;
    enclave_size = sb.st_size;
}

//std::optional<std::string> NativeEnclave::findSymbol(const uint64_t addr) const {
//    for (auto sym : binary->symbols())
//        if (sym.value() == addr - getBase())
//            return sym.name();
//    return {};
//}

inline void signal_abort(siginfo_t* info, ucontext_t* context) {
    report_crashing_addr(context);

#if NO_VM_RELOAD == 0
    //kafl_backtrace(info->si_signo);
    uint64_t reason = 0x8000000000000000ULL | context->uc_mcontext.gregs[REG_RIP] | ((uint64_t) info->si_signo << 47);
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, reason);
#endif

    struct sigaction sa = {};
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = nullptr;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGILL, &sa, nullptr);
}

//#define DEBUG
#define ENCLU_SIZE 3
void sigill_sigaction(int signal, siginfo_t* si, void* arg) {
//    assert(signal == SIGILL);
    auto* uc = (ucontext_t*) arg;

    const uint64_t rip = uc->uc_mcontext.gregs[REG_RIP];
    greg_t* const rip_s = &uc->uc_mcontext.gregs[REG_RIP];

#define QEMU
#ifdef QEMU
    if (*(uint32_t*) rip == 0x29ae0f48) // 480fae29 xrstor64 [rcx]
    {
        puts("WARNING: xrstor64 skipped");
        *rip_s += 4;
        return;
    }
    if ((*(uint32_t*) rip & 0xFFFFFF) == 0xf0c70f) // RDRAND EAX
    {
        uc->uc_mcontext.gregs[REG_RAX] = 0x45454545;
        uc->uc_mcontext.gregs[REG_EFL] = 1; // CF
        *rip_s += 3;
        return;
    }
    if ((*(uint32_t*) rip & 0xFFFFFF) == 0xf6c70f) // RDRAND ESI
    {
        uc->uc_mcontext.gregs[REG_RSI] = 0x45454545;
        uc->uc_mcontext.gregs[REG_EFL] = 1; // CF
        *rip_s += 3;
        return;
    }
#endif

    if ((*(uint32_t*) rip & ((1 << (8 * ENCLU_SIZE)) - 1)) != 0xd7010f) // ENCLU
    {
        return signal_abort(si, uc);
        abort();
    }

    const uint64_t rax = uc->uc_mcontext.gregs[REG_RAX];
    greg_t* const rax_s = &uc->uc_mcontext.gregs[REG_RAX];
    const uint64_t rbx = uc->uc_mcontext.gregs[REG_RBX];
#ifdef DEBUG
    const uint64_t rcx = uc->uc_mcontext.gregs[REG_RCX];
#endif
    const uint64_t rdx = uc->uc_mcontext.gregs[REG_RDX];

    switch (rax) {
        case 0: // EREPORT
            *(uint16_t*) rdx = 0x202; // cpu svn
            *rip_s += ENCLU_SIZE;
            return;
/*        case 1: // EGETKEY
            todo
            return;*/
        case 4: // EEXIT
#ifdef DEBUG
            printf("EEXIT (0x%lx -> 0x%lx)\n", rip, rbx);
#endif
            *rip_s = rbx; // ret or ocall
            return;
        case 5: // EACCEPT
        {
#ifdef DEBUG
            uint64_t secinfo = rbx; // SECINFO
            uint64_t epc_page = rcx; // EPC page
            printf("EACCEPT (0x%lx, 0x%lx)\n", secinfo, epc_page);
#endif
            *rax_s = 0; // return NO_ERROR
            *rip_s += ENCLU_SIZE;
            return;
        }
        case 6: // EMODPE
        {
#ifdef DEBUG
            uint64_t secinfo = rbx; // SECINFO
            uint64_t epc_page = rcx; // EPC page
            printf("EMODPE (0x%lx, 0x%lx)\n", secinfo, epc_page);
#endif
            *rip_s += ENCLU_SIZE;
            return;
        }
        default:
            printf("Unknown ENCLU function: %lu\n", rax);
            return signal_abort(si, uc);
            abort();
    }
}

bool NativeEnclave::init_entry(uint64_t tcs_page, bool skip_call) {
    assert(tcs == nullptr);
    tcs = reinterpret_cast<TCS_t*>(getBase() + tcs_page);

    struct sigaction sa = {};
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sigill_sigaction;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGILL, &sa, nullptr);

    system_features_nuc system_features{};

    tcs->cssa = 0;
    uint64_t ssa = getBase() + tcs->ossa + 0x1000 * tcs->cssa; // * ssaframesize // https://www.felixcloutier.com/x86/eenter
    ssa_gpr_t* ssa_gpr = reinterpret_cast<ssa_gpr_t*>(ssa + 0xf48); // constant offset ?

    // add space for OCALL parameter
    uint64_t _ecall_stack = reinterpret_cast<uint64_t>(fakestack) + 0x1000; // TODO: find reason for this value
    ssa_gpr->rsp_u = _ecall_stack;
    ssa_gpr->rbp_u = _ecall_stack;

    gs = (thread_data_t*) (getBase() + tcs->ogs_base);
    gs->self_addr = (sys_word_t) gs;
    fs = (thread_data_t*) (getBase() + tcs->ofs_base);
    fs->self_addr = (sys_word_t) fs;

    if (skip_call)
        return true;

    // Call init_enclave
    if (ecall_entry_intel_sdk(-1, &system_features) != (uint64_t) -1) // OCMD_ERET == -1: normal EEXIT/no OCALL
        return false; // Allow OCALL in init?

    return true;
}

/**
 * Call an ECALL by its ID
 * @param id ECALL ID (≥0); init_enclave (-1); ORET (-2)
 * @param ms ECALL marshalling structure
 * @return OCALL index (OCMD_ERET==-1 for normal exit)
 */
uint64_t NativeEnclave::ecall_entry_intel_sdk(uint64_t id, void* ms) {
    state.rdi = id;
    state.rsi = reinterpret_cast<uint64_t>(ms);

    return ecall_entry();
}

uint64_t NativeEnclave::ecall_entry() {
    assert(tcs != nullptr);

    static uintptr_t gs_outside;
    static uintptr_t fs_outside;
    syscall(SYS_arch_prctl, ARCH_GET_GS, &gs_outside);
    syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_outside);
    syscall(SYS_arch_prctl, ARCH_SET_GS, gs);
    syscall(SYS_arch_prctl, ARCH_SET_FS, fs);

    static uint64_t rsp_outside;
    static uint64_t rbp_outside;
    static RegState* cur_state;
    cur_state = &state;

    tcs->reserved1 = 42; // AEP

    state.rax = 0;
    state.rbx = reinterpret_cast<uint64_t>(tcs); // TCS
    state.rcx = (uint64_t) && eexit_label; // return address (EEXIT), 42 = QBDI fake return address

    state.rsp = state.rbp = reinterpret_cast<uint64_t>(fakestack) + 0x1000;

    asm(
    // save stack
    "mov %%rsp, %2;"
    "mov %%rbp, %3;"
    "mov %1, %%r9 ;" // enclave_entry
    "mov %0, %%rax ;" // state
    // load state
    "mov  8(%%rax), %%rbx ;"
    "mov 16(%%rax), %%rdi ;"
    "mov 24(%%rax), %%rsi ;"
    "mov 32(%%rax), %%rdx ;"
    "mov 40(%%rax), %%rcx ;"
    "mov 48(%%rax), %%rsp ;"
    "mov 56(%%rax), %%rbp ;"
    "mov (%%rax), %%rax ;"
    "jmp *%%r9 ;"
//    "call *%%r9 ;"
    : : "r" (&state), "r" (getEntry()), "m" (rsp_outside), "m" (rbp_outside)
    : "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r9"
    );

    static uint64_t rsp_inside;
    static uint64_t rbp_inside;
    static uint64_t _tmp;

    eexit_label:
    asm(
    // swap stack
    "mov %%rsp, %0;"
    "mov %%rbp, %1;"
    "mov %2, %%rsp;"
    "mov %3, %%rbp;"
    : "=m" (rsp_inside), "=m" (rbp_inside) : "m" (rsp_outside), "m" (rbp_outside)
    : "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r9"
    );
    asm(
    "mov %%rax, %0;" // rax -> _tmp
    // save state
    "mov %1, %%rax;"
    "mov %%rbx,  8(%%rax);"
    "mov %%rdi, 16(%%rax);"
    "mov %%rsi, 24(%%rax);"
    "mov %%rdx, 32(%%rax);"
    "mov %%rcx, 40(%%rax);"
    // _tmp/rax -> rbx -> state.rax
    "mov %0, %%rbx;"
    "mov %%rbx, (%%rax);"
    : "=m" (_tmp) : "m" (cur_state)
    : "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r9"
    );

    syscall(SYS_arch_prctl, ARCH_SET_GS, gs_outside);
    syscall(SYS_arch_prctl, ARCH_SET_FS, fs_outside);

    assert(state.rax == 4); // eax after EEXIT
    return get_ocall_id();
}

/// Resume after OCALL (ORET)
/// \return Next OCALL ID
uint64_t NativeEnclave::ecall_oret() {
    return ecall_entry_intel_sdk(-2, nullptr);
}
/// Get ID of OCALL after ECALL/EEXIT. OCALL state is assumed.
/// \return OCALL ID
uint64_t NativeEnclave::get_ocall_id() const {
    return state.rdi;
}
/// Get marshalling struct of OCALL. OCALL state is assumed.
/// \return ms
void** NativeEnclave::get_ocall_ms() const {
    auto* gprState = &state;
    uint64_t params[5] = {
        gprState->rdi, // OCALL ID
        ((uint64_t*) gprState->rbp)[-8], // frame_arg2 // ocall_table
        gprState->rsi, // arg/ms
        ((uint64_t*) gprState->rbp)[-6], // frame_arg4
        ((uint64_t*) gprState->rbp)[-10], // frame_arg0
    };

    return (void**) params[2];
}
void NativeEnclave::apply_layout(layout_entry* table) {
    layout = table;
    for (int i = 0; table[i].size; i++)
        if (table[i].type == 2)
            ::mprotect((void*) (table[i].addr + enclave_base), table[i].size, table[i].perm);
}
