#ifndef NATIVE_SGX_RUNNER_GUARDEDBUFFER_H
#define NATIVE_SGX_RUNNER_GUARDEDBUFFER_H

#include <cstddef>
#include <cstdint>

#include "Buffer.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

class GuardedBuffer : public Buffer {
private:
    void* internal_addr = nullptr;
    size_t internal_size = 0;

public:
    explicit GuardedBuffer(size_t new_len = sizeof(void*));
    ~GuardedBuffer() override;

    bool isInGuardPage(void* addr) const override;

    [[nodiscard]] bool resize(size_t new_len) override;
};


#endif //NATIVE_SGX_RUNNER_GUARDEDBUFFER_H
