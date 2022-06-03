// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define WRITE_REG(pkt, op, val) hex_write_reg(pkt, op, val)
#define READ_REG(pkt, op, tmp_reg) hex_read_reg(pkt, op, tmp_reg)
#define ISA2REG(hi, var, tmp_reg) hex_isa_to_reg(hi, var, tmp_reg)
#define ISA2IMM(hi, var) hex_isa_to_imm(hi, var)
#define HEX_REGFIELD(prop, reg) hex_get_rf_property_val(prop, reg)
#define HEX_EXTRACT64(val, start, len) hex_extract64(val, start, len)
#define HEX_SEXTRACT64(val, start, len) hex_sextract64(val, start, len)
#define HEX_DEPOSIT64(val, start, len, fieldval) hex_deposit64(val, start, len, fieldval)
#define HEX_GET_NPC(pkt) hex_get_npc(pkt)
#define HEX_WRITE_GLOBAL(name, val) hex_write_global(name, val)
#define INC(val, size) ADD(val, UN(size, 1))
#define DEC(val, size) SUB(val, UN(size, 1))
#define HEX_STORE_SLOT_CANCELLED(pkt, slot) hex_cancel_slot(pkt, slot)
#define HEX_FCIRC_ADD(bundle, RxV, offset, mu, CS) hex_fcircadd(bundle, RxV, offset, mu, CS)
#define HEX_GET_CORRESPONDING_CS(pkt, Mu) hex_get_corresponding_cs(pkt, Mu)
#define HEX_GET_INSN_RMODE(insn)                   (insn->fround_mode)
#define HEX_D_TO_SINT(mode, fval)                  F2SINT(64, mode, fval)
#define HEX_F_TO_SINT(mode, fval)                  F2SINT(32, mode, fval)
#define HEX_D_TO_INT(mode, fval)                   F2INT(64, mode, fval)
#define HEX_F_TO_INT(mode, fval)                   F2INT(32, mode, fval)

#define HEX_IMMUTABLE_REG (~0)
#define HEX_NOT_MASKED 0
