// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

RZ_API RZ_BORROW RzConfig *hexagon_get_config();
RZ_API void hex_extend_op(HexState *state, RZ_INOUT HexOp *op, const bool set_new_extender, const ut32 addr);
int resolve_n_register(const int reg_num, const ut32 addr, const HexPkt *p);
int hexagon_disasm_instruction(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, HexPkt *pkt);
void hexagon_disasm_0x0(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x1(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x2(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x3(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x4(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x5(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x6(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x7(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x8(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x9(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xa(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xb(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xc(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xd(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xe(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x0(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x1(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x2(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x3(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x4(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x5(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x6(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x7(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x8(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x9(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xa(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xb(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xc(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xd(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xe(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
