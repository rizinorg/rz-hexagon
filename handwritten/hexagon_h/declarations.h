// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

void hex_extend_op(RZ_INOUT HexOp *op, const bool set_new_extender, const ut32 addr);
int resolve_n_register(const int reg_num, const HexPkt *p);
int hexagon_disasm_instruction(const ut32 hi_u32, RZ_INOUT HexInsn *hi, HexPkt *pkt);
void hexagon_disasm_0x0(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x1(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x2(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x3(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x4(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x5(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x6(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x7(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x8(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x9(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xa(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xb(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xc(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xd(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xe(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x0(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x1(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x2(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x3(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x4(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x5(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x6(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x7(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x8(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x9(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xa(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xb(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xc(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xd(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xe(const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
