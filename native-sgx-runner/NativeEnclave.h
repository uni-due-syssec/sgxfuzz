
#ifndef AFL_LOADER_QBDIENCLAVE_H
#define AFL_LOADER_QBDIENCLAVE_H

#include <cstddef>
#include <cstdint>
#include <vector>
#include <cassert>
#include "sgx_types.h"

#define STACK_SIZE 0x10000

#define STR_EXPAND(tok) #tok
#define LINK_DATA(var, path, section, align, perm) \
extern uint8_t var ##_start[]; \
extern uint8_t var ##_end; \
__asm__( \
".section \"" section "\", \"" perm "\", @progbits\n" \
".align " align "\n" \
#var"_start:\n" \
".incbin \"" STR_EXPAND(path) "\"\n" \
#var"_end:\n" \
"" \
".previous\n" \
);
#define LINK_ENCLAVE(var, path) LINK_DATA(var, path, ".encl", "0x100000", "awx")

typedef struct _RegState {
    uint64_t rax;
    uint64_t rbx;

    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rcx;

    uint64_t rsp;
    uint64_t rbp;
} RegState;

typedef struct layout_entry {
    uint64_t addr;
    uint64_t size;
    unsigned char perm;
    unsigned char type;
} __attribute__((__packed__)) layout_entry;

class NativeEnclave {
protected:
    uint8_t* fakestack = nullptr;

    uint64_t enclave_base = 0;
    uint64_t enclave_size = 0;
    TCS_t* tcs = nullptr;
    layout_entry* layout = nullptr;

    RegState state{};
    thread_data_t* fs = nullptr;
    thread_data_t* gs = nullptr;
private:
    explicit NativeEnclave();
    void load_enclave_dump(void* address, const char* file_path);

public:
    NativeEnclave(const char* dump, void* base_address);
    NativeEnclave(void* enc_base, size_t enc_size);
    NativeEnclave(const NativeEnclave&) = delete;
    NativeEnclave(NativeEnclave&& other) = default;
    NativeEnclave& operator=(const NativeEnclave&) = delete;
    virtual ~NativeEnclave();

    [[nodiscard]] uint64_t getSize() const { return enclave_size; }
    [[nodiscard]] uint64_t getBase() const { return enclave_base; }
    [[nodiscard]] const layout_entry* getLayout() const { return layout; }

//    void init();
//    void trace(bool val = true);
    bool init_entry(uint64_t tcs_page, bool skip_call = false);
    void apply_layout(layout_entry* table);
//    uint64_t call(const char* func, const std::vector<uint64_t>& args = {});
    uint64_t ecall_entry_intel_sdk(uint64_t id, void* ms);
    uint64_t ecall_oret();

    [[nodiscard]] uint64_t get_ocall_id() const;
    [[nodiscard]] void** get_ocall_ms() const;

//    uint64_t getAddr(const char* symbol) const { return binary->get_symbol(symbol).value() + getBase(); }
//    std::optional<std::string> findSymbol(uint64_t addr) const;
    uint64_t getEntry() {
        assert(tcs);
        return getBase() + tcs->oentry;
    }

protected:
    uint64_t ecall_entry();
};

#endif //AFL_LOADER_QBDIENCLAVE_H
