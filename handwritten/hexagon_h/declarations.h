// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
//
// SPDX-License-Identifier: LGPL-3.0-only

void hex_op_extend(RZ_INOUT HexOp *op, const bool set_new_extender);
void hex_set_pkt_info(RZ_INOUT HexPktInfo* pkt_info, const ut32 addr);
int hexagon_disasm_instruction(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0x0(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0x1(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0x2(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0x3(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0x4(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0x5(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0x6(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0x7(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0x8(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0x9(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0xa(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0xb(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0xc(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0xd(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_0xe(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0x0(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0x1(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0x2(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0x3(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0x4(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0x5(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0x6(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0x7(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0x8(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0x9(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0xa(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0xb(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0xc(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0xd(ut32 hi_u32, HexInsn *hi, ut32 addr);
void hexagon_disasm_duplex_0xe(ut32 hi_u32, HexInsn *hi, ut32 addr);

