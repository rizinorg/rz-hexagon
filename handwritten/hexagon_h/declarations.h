// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

RZ_API RZ_BORROW RzConfig *hexagon_get_config();
RZ_API void hex_extend_op(HexState *state, RZ_INOUT HexOp *op, const bool set_new_extender, const ut32 addr);
int resolve_n_register(const int reg_num, const ut32 addr, const HexPkt *p);
int hexagon_disasm_instruction(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsnContainer *hi, HexPkt *pkt);
RZ_API const HexOp hex_alias_to_op(HexRegAlias alias, bool tmp_reg);
RZ_API const char *hex_alias_to_reg_name(HexRegAlias alias, bool tmp_reg);
RZ_API const HexOp hex_explicit_to_op(ut32 reg_num, HexRegClass reg_class, bool tmp_reg);
