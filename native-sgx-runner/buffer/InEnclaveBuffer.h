#ifndef NATIVE_SGX_RUNNER_INENCLAVEBUFFER_H
#define NATIVE_SGX_RUNNER_INENCLAVEBUFFER_H

#include <cstddef>
#include <sys/mman.h>
#include <list>

#include "../NativeEnclave.h"
#include "Buffer.h"

std::list<uintptr_t> InEnclaveBuffer_used_pages;

class InEnclaveBuffer : public Buffer {
protected:
    bool readable;
public:
    explicit InEnclaveBuffer(NativeEnclave* enclave, bool readable = true, size_t new_len = sizeof(void*)) : readable(readable) {
        if (readable) {
            buf = (char*) find_gap_page(enclave, 2 * PAGE_SIZE);
            assert(buf);
            if (::mprotect(buf, PAGE_SIZE, PROT_READ | PROT_WRITE)
                || ::mprotect(buf + PAGE_SIZE, PAGE_SIZE, PROT_NONE))
                throw std::system_error(errno, std::generic_category());
        } else {
            buf = (char*) find_gap_page(enclave, PAGE_SIZE);
            assert(buf);
            if (::mprotect(buf, PAGE_SIZE, PROT_NONE) != 0)
                throw std::system_error(errno, std::generic_category());
        }
        InEnclaveBuffer_used_pages.push_back((uintptr_t) buf);
        assert(resize(new_len));
    }
    ~InEnclaveBuffer() override = default;

    bool isReadable() const override { return readable; }

    bool resize(size_t new_len) override {
        const bool do_resize = new_len <= PAGE_SIZE;
        if (do_resize) len = new_len;
        return do_resize;
    };

private:
    static uintptr_t find_rw_page(const NativeEnclave* enclave) {
        const layout_entry* table = enclave->getLayout();
        assert(table);

        uintptr_t buf = 0;
        for (int i = 0; table[i].size; i++)
            if (table[i].type == 2 && table[i].perm == (PROT_READ | PROT_WRITE)) {
                uint64_t* section = (uint64_t*) (enclave->getBase() + table[i].addr); // NOLINT(modernize-use-auto)
                if (*section == 0xccccccccccccccccL)
                    buf = (uintptr_t) section;
            }
        return buf;
    }

    static uintptr_t find_gap_page(const NativeEnclave* enclave, size_t min_size = PAGE_SIZE) {
        const layout_entry* table = enclave->getLayout();
        assert(table);

        for (int i = 0; table[i].size; i++)
            if (table[i].type == 2 && table[i + 1].type > 0
                && table[i].addr + table[i].size + min_size < table[i + 1].addr) {
                uintptr_t buf = enclave->getBase() + table[i].addr + table[i].size;
                if (std::find(InEnclaveBuffer_used_pages.cbegin(), InEnclaveBuffer_used_pages.cend(), buf) != InEnclaveBuffer_used_pages.cend())
                    continue;
                return buf;
            }
        return 0;
    }

public:
    bool set_data(size_t offset, const char* data, size_t data_len) override {
        if (!readable) {
            if (getLen() < offset + data_len)
                if (!resize(offset + data_len))
                    return false;
            return true; // ignore writes
        } else
            return Buffer::set_data(offset, data, data_len);
    }
};


#endif //NATIVE_SGX_RUNNER_INENCLAVEBUFFER_H
