//
// Created by dingjing on 25-6-16.
//

#include "disasm.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <c/clib.h>

#include "hook-func-internal.h"

#ifdef ARCH_ARM64
#define CS_ARCH CS_ARCH_ARM64
#define CS_MODE CS_MODE_LITTLE_ENDIAN
#endif

#ifdef ARCH_X86_64
#define CS_ARCH CS_ARCH_X86
#define CS_MODE CS_MODE_64
#endif

#ifdef ARCH_X86
#define CS_ARCH CS_ARCH_X86
#define CS_MODE CS_MODE_32
#endif

#define LOG_DETAIL 0

#define HEX(x) ((x) < 10 ? (x) + '0' : (x) - 10 + 'A')

int hook_func_disasm_init(HookFuncDisAsm* disAsm, HookFunc* funcHook, const Insn* code, size_t codeSize, size_t address)
{
    cs_err err;

    disAsm->funcHook = funcHook;
    disAsm->index = 0;
    if ((err = cs_open(CS_ARCH, CS_MODE, &disAsm->handle)) != 0) {
        hook_func_set_error_message(funcHook, "cs_open error: %s", cs_strerror(err));
        C_LOG_WARNING("cs_open error: %s", cs_strerror(err));
        return HOOK_FUNC_ERROR_INTERNAL_ERROR;
    }
    if ((err = cs_option(disAsm->handle, CS_OPT_DETAIL, CS_OPT_ON)) != 0) {
        hook_func_set_error_message(funcHook, "cs_option error: %s", cs_strerror(err));
        C_LOG_WARNING("cs_option error: %s", cs_strerror(err));
        cs_close(&disAsm->handle);
        return HOOK_FUNC_ERROR_INTERNAL_ERROR;
    }
    if ((disAsm->count = cs_disasm(disAsm->handle, (const uint8_t*)code, codeSize * sizeof(Insn), address, 0, &disAsm->insns)) == 0) {
        err = cs_errno(disAsm->handle);
        hook_func_set_error_message(funcHook, "disassemble error: %s", cs_strerror(err));
        C_LOG_WARNING("disassemble error: %s", cs_strerror(err));
        cs_close(&disAsm->handle);
        return HOOK_FUNC_ERROR_DISASSEMBLY;
    }

    return 0;
}

void hook_func_disasm_cleanup(HookFuncDisAsm* disAsm)
{
    if (disAsm->count != 0) {
        cs_free(disAsm->insns, disAsm->count);
    }
    cs_close(&disAsm->handle);
}

int hook_func_disasm_next(HookFuncDisAsm* disAsm, const HookFuncInsn** nextInsn)
{
    if (disAsm->index < disAsm->count) {
        *nextInsn = &disAsm->insns[disAsm->index++];
        return 0;
    }
    else {
        C_LOG_WARNING("end of instruction.");
        return HOOK_FUNC_ERROR_END_OF_INSTRUCTION;
    }
}

static const char *reg_name(csh handle, unsigned int reg_id)
{
    const char *name = cs_reg_name(handle, reg_id);
    return name ? name : "?";
}

static const char *group_name(csh handle, unsigned int grp_id)
{
    const char *name = cs_group_name(handle, grp_id);
    return name ? name : "?";
}

void hook_func_disasm_log_instruction(HookFuncDisAsm* disAsm, const HookFuncInsn* insn)
{
    HookFunc* funcHook = disAsm->funcHook;
    char hex[sizeof(insn->bytes) * 3];
    uint16_t i;

    for (i = 0; i < insn->size; i++) {
        hex[i * 3 + 0] = HEX(insn->bytes[i] >> 4);
        hex[i * 3 + 1] = HEX(insn->bytes[i] & 0x0F);
        hex[i * 3 + 2] = ' ';
    }
    hex[insn->size * 3 - 1] = '\0';
    C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  %x (%02d) %-24s %s%s%s",
        (size_t)insn->address, insn->size, hex, insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);

#if 0
    cs_detail *detail = insn->detail;
    if (detail == NULL) {
        return;
    }
    if (detail->regs_read_count > 0) {
        C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  regs_read:");
        for (i = 0; i < insn->detail->regs_read_count; i++) {
            C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "   %s ", reg_name(disAsm->handle, insn->detail->regs_read[i]));
        }
    }
    if (detail->regs_write_count > 0) {
        C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  regs_write:");
        for (i = 0; i < insn->detail->regs_write_count; i++) {
            C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "   %s ", reg_name(disAsm->handle, insn->detail->regs_write[i]));
        }
    }
    if (detail->groups_count > 0) {
        C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  groups:");
        for (i = 0; i < insn->detail->groups_count; i++) {
            C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "   %s ", group_name(disAsm->handle, insn->detail->groups[i]));
        }
    }
#if defined(ARCH_X86_64) || defined(ARCH_X86)
    const csh handle = disAsm->handle;
    cs_x86 *x86 = &detail->x86;
    if (x86->encoding.modrm_offset != 0) {
        C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  encoding.modrm_offset: %u", x86->encoding.modrm_offset);
    }
    if (x86->encoding.disp_offset != 0) {
        C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  encoding.disp_offset: %u, size: %u", x86->encoding.disp_offset, x86->encoding.disp_size);
    }
    if (x86->encoding.imm_offset != 0) {
        C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  encoding.imm_offset: %u, size: %u", x86->encoding.imm_offset, x86->encoding.imm_size);
    }
    if (x86->encoding.disp_offset != 0) {
        int64_t i64;
        const char *sign;

        if (x86->disp >= 0) {
            i64 = x86->disp;
            sign = "";
        }
        else {
            i64 = -x86->disp;
            sign = "-";
        }
        C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  disp: %s0x%X", sign, i64);
    }
    if (x86->sib_index != X86_REG_INVALID) {
        C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  sib_index: %s, sib_scale: %u", reg_name(handle, x86->sib_index), x86->sib_scale);
    }
    if (x86->sib_base != X86_REG_INVALID) {
        C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  sib_base: %s", reg_name(handle, x86->sib_base));
    }
    if (x86->op_count > 0) {
        for (i = 0; i < x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            int64_t i64;
            const char *sign;
            switch (op->type) {
            case X86_OP_INVALID:
                C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  operands[%u]: INVALID", i);
                break;
            case X86_OP_REG:
                C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  operands[%u]: REG %s (size:%u)", i, reg_name(handle, op->reg), op->size);
                break;
            case X86_OP_IMM:
                if (op->imm >= 0) {
                    i64 = op->imm;
                    sign = "";
                }
                else {
                    i64 = -op->imm;
                    sign = "-";
                }
                C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  operands[%u]: IMM %s0x%X", i, sign, i64);
                break;
            case X86_OP_MEM:
                if (op->mem.disp >= 0) {
                    i64 = op->mem.disp;
                    sign = "";
                } else {
                    i64 = -op->mem.disp;
                    sign = "-";
                }
                C_LOG_WRITE_FILE(C_LOG_LEVEL_DEBUG, "  operands[%u]: MEM seg:%s, base:%s, index:%s, scale:%u, disp:%s0x%X",
                             i, reg_name(handle, op->mem.segment),
                             reg_name(handle, op->mem.base), reg_name(handle, op->mem.index), op->mem.scale, sign, i64);
                break;
            }
        }
    }
#endif /* defined(ARCH_X86_64) || defined(ARCH_X86) */
#endif
}

#if defined(ARCH_ARM64)
// Check only registers in FUNCHOOK_ARM64_CORRUPTIBLE_REGS
static uint32_t cs2funchook_reg(uint16_t reg)
{
    switch (reg) {
    case ARM64_REG_W9:
    case ARM64_REG_X9:
        return HOOK_FUNC_ARM64_REG_X9;
    case ARM64_REG_W10:
    case ARM64_REG_X10:
        return HOOK_FUNC_ARM64_REG_X10;
    case ARM64_REG_W11:
    case ARM64_REG_X11:
        return HOOK_FUNC_ARM64_REG_X11;
    case ARM64_REG_W12:
    case ARM64_REG_X12:
        return HOOK_FUNC_ARM64_REG_X12;
    case ARM64_REG_W13:
    case ARM64_REG_X13:
        return HOOK_FUNC_ARM64_REG_X13;
    case ARM64_REG_W14:
    case ARM64_REG_X14:
        return HOOK_FUNC_ARM64_REG_X14;
    case ARM64_REG_W15:
    case ARM64_REG_X15:
        return HOOK_FUNC_ARM64_REG_X15;
    default:
        return 0;
    }
}

HookFuncInsnInfo hook_func_disasm_arm64_insn_info(HookFuncDisAsm* disasm, const HookFuncInsn* insn)
{
    const cs_detail *detail = insn->detail;
    HookFuncInsnInfo info = {0,};
    cs_regs rregs, wregs;
    uint8_t rregs_cnt, wregs_cnt, i;

    switch (insn->id) {
    case ARM64_INS_ADR:
        info.insnId = HOOK_FUNC_ARM64_INSN_ADR;
        break;
    case ARM64_INS_ADRP:
        info.insnId = HOOK_FUNC_ARM64_INSN_ADRP;
        break;
    case ARM64_INS_B:
        if (detail->arm64.cc == ARM64_CC_INVALID) {
            info.insnId = HOOK_FUNC_ARM64_INSN_B;
        } else {
            info.insnId = HOOK_FUNC_ARM64_INSN_B_cond;
        }
        break;
    case ARM64_INS_BL:
        info.insnId = HOOK_FUNC_ARM64_INSN_BL;
        break;
    case ARM64_INS_CBNZ:
        info.insnId = HOOK_FUNC_ARM64_INSN_CBNZ;
        break;
    case ARM64_INS_CBZ:
        info.insnId = HOOK_FUNC_ARM64_INSN_CBZ;
        break;
    case ARM64_INS_LDR:
        info.insnId = HOOK_FUNC_ARM64_INSN_LDR;
        break;
    case ARM64_INS_LDRSW:
        info.insnId = HOOK_FUNC_ARM64_INSN_LDRSW;
        break;
    case ARM64_INS_PRFM:
        info.insnId = HOOK_FUNC_ARM64_INSN_PRFM;
        break;
    case ARM64_INS_TBNZ:
        info.insnId = HOOK_FUNC_ARM64_INSN_TBNZ;
        break;
    case ARM64_INS_TBZ:
        info.insnId = HOOK_FUNC_ARM64_INSN_TBZ;
        break;
    }

    if (!cs_regs_access(disasm->handle, insn, rregs, &rregs_cnt, wregs, &wregs_cnt)) {
        for (i = 0; i < rregs_cnt; i++) {
            info.regs |= cs2funchook_reg(rregs[i]);
        }
        for (i = 0; i < wregs_cnt; i++) {
            info.regs |= cs2funchook_reg(wregs[i]);
        }
    }
    return info;
}
#endif /* defined(ARCH_ARM64) */

#if defined(ARCH_X86) || defined(ARCH_X86_64)
void hook_func_disasm_x86_rip_relative(HookFuncDisAsm* disAsm, const HookFuncInsn* insn, RipRelative* relDisp, RipRelative* relImm)
{
    int i;
    cs_x86 *x86 = &insn->detail->x86;

    memset(relDisp, 0, sizeof(RipRelative));
    memset(relImm, 0, sizeof(RipRelative));

    // 如果指令的立即数(如果存在)在cs_insn.bytes数组中的起始位置。
    // 通过此值可以从指令的原始字节中提取立即数的值
    if (x86->encoding.imm_offset != 0) {
        for (i = 0; i < insn->detail->groups_count; i++) {
            // 相对跳转指令分组
            if (insn->detail->groups[i] == X86_GRP_BRANCH_RELATIVE) {
                intptr_t imm = 0;
                if (x86->encoding.imm_size == 4) {
                    imm = *(int32_t*)(insn->bytes + x86->encoding.imm_offset);
                } else if (x86->encoding.imm_size == 1) {
                    imm = *(int8_t*)(insn->bytes + x86->encoding.imm_offset);
                } else {
                    // TODO:
                }
                // Fix IP-relative jump or call:
                // cs_insn->size: 表示指令长度，记录指令在内存或二进制中的占用字节数，直接对应cs_insn->bytes数组中有效字节的数量
                // 反汇编中，size用于确定当前指令的结束位置和下一条指令的起始地址
                // (next_address = address + size)
                relImm->addr = (uint8_t*)(size_t)(insn->address + insn->size + imm);
                relImm->rAddr = imm;
                relImm->size = x86->encoding.imm_size * 8;      // 指令中立即数的字节长度 * 8, 立即数的位宽
                relImm->offset = x86->encoding.imm_offset;
                break;
            }
        }
    }

    // disp_offset，表示x86指令中偏移量在指令字节流(cs_insn->bytes)中的起始偏移量。
    if (x86->encoding.disp_offset != 0) {
        for (i = 0; i < x86->op_count; i++) {
            const cs_x86_op *op = &x86->operands[i];
            // X86_OP_MEM：内存操作数
            // RIP：表示指令指针寄存器
            if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
                // Fix IP-relative addressing such as:
                //    mov eax, dword ptr [rip + 0x236eda]
                //    jmp qword ptr [rip + 0x239468]
                //    call qword ptr [rip + 0x239446]
                //    cmp dword ptr [rip + 0x2d2709], 0
                relDisp->addr = (uint8_t*)(size_t)(insn->address + insn->size + x86->disp);
                relDisp->rAddr = (intptr_t)x86->disp;
                relDisp->size = x86->encoding.disp_size * 8;
                relDisp->offset = x86->encoding.disp_offset;
            }
        }
    }
}
#endif /* defined(ARCH_X86) || defined(ARCH_X86_64) */
