// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
//
// SPDX-License-Identifier: LGPL-3.0-only

bool hex_if_duplex(ut32 insn_word);
void hex_op_extend(HexOp *op, bool set_new_extender);
void hex_set_pkt_info(RZ_INOUT HexPktInfo* pkt_info);
int hexagon_disasm_instruction(ut32 hi_u32, HexInsn *hi, ut32 addr);

