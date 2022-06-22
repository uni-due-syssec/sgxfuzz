#pragma once

#include <signal.h>
//#include <sys/ucontext.h>

//greg_t get_crashing_addr(greg_t ip_reg);
greg_t get_crashing_addr(gregset_t regs);
