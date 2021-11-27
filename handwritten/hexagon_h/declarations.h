// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

RZ_API void hex_extend_op(HexState *state, RZ_INOUT HexOp *op, const bool set_new_extender, const ut32 addr);
int resolve_n_register(const int reg_num, const ut32 addr, const HexPkt *p);
int hexagon_disasm_instruction(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, HexPkt *pkt);
void hexagon_disasm_0x0(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x1(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x2(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x3(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x4(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x5(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x6(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x7(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x8(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x9(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xa(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xb(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xc(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xd(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xe(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x0(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x1(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x2(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x3(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x4(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x5(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x6(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x7(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x8(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x9(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xa(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xb(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xc(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xd(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xe(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
