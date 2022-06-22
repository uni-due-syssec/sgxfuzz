#ifndef NATIVE_SGX_RUNNER_BUFFER_H
#define NATIVE_SGX_RUNNER_BUFFER_H

#include <cstring>

class Buffer {
protected:
    char* buf = nullptr;
    size_t len = 0;

public:
    explicit Buffer() = default;
    virtual ~Buffer() = default;
    Buffer(const Buffer&) = delete;

    [[nodiscard]] virtual char* getBuf() const { return buf; }
    [[nodiscard]] virtual size_t getLen() const { return len; }

    virtual bool isInGuardPage(void* addr) const { return false; }
    virtual bool isReadable() const { return true; }

    [[nodiscard]] virtual bool resize(size_t new_len) = 0;
    [[nodiscard]] virtual bool set_data(size_t offset, const char* data, size_t data_len) {
        if (getLen() < offset + data_len)
            if (!resize(offset + data_len))
                return false;
        if (data)
            memcpy(&buf[offset], data, data_len);
        else
            bzero(&buf[offset], data_len);
        return true;
    }
};

#endif //NATIVE_SGX_RUNNER_BUFFER_H
