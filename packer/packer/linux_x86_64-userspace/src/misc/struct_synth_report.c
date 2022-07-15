#define _GNU_SOURCE
#include <Zydis/Zydis.h>

#include <signal.h>
#include <ucontext.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "nyx.h"
#include "misc/struct_synth_report.h"

// This stuff is in a separate file as the includes of Zydis.h import __assert which is already defined in crash_handler.c


greg_t get_reg_val(ZydisRegister reg, gregset_t regs) {
    const ZydisRegister reg_enclosing = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);

    switch(reg_enclosing) {
        case ZYDIS_REGISTER_RAX: { return regs[REG_RAX]; }
        case ZYDIS_REGISTER_RCX: { return regs[REG_RCX]; }
        case ZYDIS_REGISTER_RDX: { return regs[REG_RDX]; }
        case ZYDIS_REGISTER_RBX: { return regs[REG_RBX]; }
        case ZYDIS_REGISTER_RSP: { return regs[REG_RSP]; }
        case ZYDIS_REGISTER_RBP: { return regs[REG_RBP]; }
        case ZYDIS_REGISTER_RSI: { return regs[REG_RSI]; }
        case ZYDIS_REGISTER_RDI: { return regs[REG_RDI]; }
        case ZYDIS_REGISTER_R8: { return regs[REG_R8]; }
        case ZYDIS_REGISTER_R9: { return regs[REG_R9]; }
        case ZYDIS_REGISTER_R10: { return regs[REG_R10]; }
        case ZYDIS_REGISTER_R11: { return regs[REG_R11]; }
        case ZYDIS_REGISTER_R12: { return regs[REG_R12]; }
        case ZYDIS_REGISTER_R13: { return regs[REG_R13]; }
        case ZYDIS_REGISTER_R14: { return regs[REG_R14]; }
        case ZYDIS_REGISTER_R15: { return regs[REG_R15]; }
        default: {
            hprintf("struct_synth_get_crashing_addr: Unhandled register: %d", reg_enclosing);
            return 0;
        }
    }
}

int readable(void* addr) {
    static int fd = -1;
    if (fd < 0)
        fd = open("/tmp/mem_test", O_RDWR | O_CREAT, 0600);
    int err = write(fd, addr, 1);
    return err == 1;
}

greg_t get_crashing_addr(gregset_t regs) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    ZydisDecodedInstruction instruction;
    ZyanU8* ip = (ZyanU8*) regs[REG_RIP];

    if(!readable(ip)) {
        return 0x99;
    }

    if(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, ip, 20, &instruction))) {
//        int reg_found = 0;
        greg_t reg_val = 0;

        for(int i = 0; i < instruction.operand_count; ++i) {
            if(instruction.operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY/* && reg_found == 0*/) {
                reg_val = 0;
//                reg_found = 1;

                // Cases:
                // [base]
                // [base + disp]
                // [disp]
                // [base + index*scale]
                // [base + index*scale + disp]

                if(instruction.operands[i].mem.base != ZYDIS_REGISTER_NONE) {
                    reg_val = get_reg_val(instruction.operands[i].mem.base, regs);
                }

                if(instruction.operands[i].mem.index != ZYDIS_REGISTER_NONE) {
                    reg_val += get_reg_val(instruction.operands[i].mem.index, regs) * instruction.operands[i].mem.scale;
                }

                if(instruction.operands[i].mem.disp.has_displacement) {
                    reg_val += instruction.operands[i].mem.disp.value;
                }

            }/* else if(instruction.operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && reg_found > 0) {
                hprintf("struct_synth_get_crashing_addr: Multiple mem operands");
            }*/
        }

        return reg_val;
    } else {
        hprintf("struct_synth_get_crashing_addr: Failed to parse instruction at %llu", regs[REG_RIP]);
        return 0;
    }
}
