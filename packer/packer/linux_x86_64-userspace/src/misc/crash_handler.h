#pragma once

#include <stdbool.h>
#include <signal.h>
#include <unistd.h>


void config_handler(void);
void init_crash_handling(void);

void set_struct_synth_addrs(const char* addrs, ssize_t len);

/* test asan */
void fail(void);