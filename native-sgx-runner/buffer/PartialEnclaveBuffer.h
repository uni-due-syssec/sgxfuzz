#ifndef NATIVE_SGX_RUNNER_PARTIALENCLAVEBUFFER_H
#define NATIVE_SGX_RUNNER_PARTIALENCLAVEBUFFER_H

#include <cstddef>
#include <sys/mman.h>

#include "../NativeEnclave.h"
#include "Buffer.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x10000
#endif

#define INENCLAVE_PART 1

class PartialEnclaveBuffer : public Buffer {
protected:
    void* internal_addr;
    bool readable;
public:
    explicit PartialEnclaveBuffer(NativeEnclave* enclave, bool readable = true, size_t new_len = sizeof(void*)) : readable(readable) {
        assert(enclave);
        auto perm = PROT_READ | PROT_WRITE;
        if (!readable)
            perm = 0;
        internal_addr = mmap((void*) (enclave->getBase() - PAGE_SIZE), PAGE_SIZE, perm, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        assert(resize(new_len));
    }
    ~PartialEnclaveBuffer() override {
        munmap(internal_addr, PAGE_SIZE);
    };

    bool isInGuardPage(void* addr) const override {
        return (uintptr_t) internal_addr + PAGE_SIZE + INENCLAVE_PART <= (uintptr_t) addr && (uintptr_t) addr < (uintptr_t) internal_addr + 2 * PAGE_SIZE;
    }

    bool isReadable() const override { return readable; }

    bool resize(size_t new_len) override {
        if (new_len > PAGE_SIZE)
            return false;

        const void* old_buf = buf;
        const size_t old_len = len;

        len = new_len;
        buf = (char*) ((uintptr_t) internal_addr + PAGE_SIZE - len + INENCLAVE_PART);

        if (new_len)
            memmove(buf, old_buf, old_len < (len - INENCLAVE_PART) ? old_len : (len - INENCLAVE_PART));

        return true;
    };

    bool set_data(size_t offset, const char* data, size_t data_len) override {
        if (getLen() < offset + data_len) {
            if (!resize(offset + data_len))
                return false;
        }

        if (!readable)
            return true; // ignore write

        size_t copy_len = data_len;
        if (offset + data_len > len - INENCLAVE_PART) {
            copy_len = len - INENCLAVE_PART - offset;
        }

        if (data)
            memcpy(&buf[offset], data, copy_len);
        else
            bzero(&buf[offset], copy_len);
        return true;
    }
};


#endif //NATIVE_SGX_RUNNER_PARTIALENCLAVEBUFFER_H
