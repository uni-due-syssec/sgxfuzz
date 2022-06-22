
#include "GuardedBuffer.h"
#include <sys/mman.h>
#include <cassert>
#include <cstdint>
#include <cstring>

#include <errno.h>
#include <stdio.h>
extern "C" {
#include "../libnyx.h"
#include "../kafl_user.h"
}

GuardedBuffer::GuardedBuffer(size_t new_len) {
    internal_size = new_len / PAGE_SIZE * PAGE_SIZE + PAGE_SIZE;
    if (new_len % PAGE_SIZE != 0)
        internal_size += PAGE_SIZE;

    internal_addr = mmap(nullptr, internal_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(internal_addr == MAP_FAILED)
    kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t) &errno);
//    dprintf(2, "errno: %d\n", errno);
    assert(internal_addr != MAP_FAILED);
    assert(mprotect((void*) ((uintptr_t) internal_addr + internal_size - PAGE_SIZE), PAGE_SIZE, PROT_NONE) == 0);

    assert(resize(new_len));
}

GuardedBuffer::~GuardedBuffer() {
    munmap(internal_addr, internal_size);
}
bool GuardedBuffer::resize(size_t new_len) {
    if (new_len > internal_size - PAGE_SIZE)
        return false;

    void* old_buf = buf;
    size_t old_len = len;

    len = new_len;
    buf = (char*) ((uintptr_t) internal_addr + internal_size - len - PAGE_SIZE);

    if (old_buf)
        memmove(buf, old_buf, old_len < len ? old_len : len);

    return true;
}

bool GuardedBuffer::isInGuardPage(void* addr) const {
    return (uintptr_t) internal_addr + internal_size - PAGE_SIZE <= (uintptr_t) addr && (uintptr_t) addr < (uintptr_t) internal_addr + internal_size;
}
