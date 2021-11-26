// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define HEX_PKT_UNK  "?   "
#define HEX_PKT_SINGLE "[   "
#define HEX_PKT_FIRST_UTF8 "┌   "
#define HEX_PKT_MID_UTF8   "│   "
#define HEX_PKT_LAST_UTF8  "└   "
#define HEX_PKT_FIRST "/   "
#define HEX_PKT_MID   "|   "
#define HEX_PKT_LAST  "\\   "
#define HEX_PKT_ELOOP_01_UTF8 "     ∎ endloop01"
#define HEX_PKT_ELOOP_1_UTF8 "     ∎ endloop1"
#define HEX_PKT_ELOOP_0_UTF8 "     ∎ endloop0"
#define HEX_PKT_ELOOP_01 "     < endloop01"
#define HEX_PKT_ELOOP_1 "     < endloop1"
#define HEX_PKT_ELOOP_0 "     < endloop0"

RZ_API void hex_insn_free(HexInsn *i);
RZ_API void hex_const_ext_free(HexConstExt *ce);
RZ_API HexState *hexagon_get_state();
RZ_API void hexagon_reverse_opcode(const RzAsm *rz_asm, HexReversedOpcode *rz_reverse, const ut8 *buf, const ut64 addr);
RZ_API ut8 hexagon_get_pkt_index_of_addr(const ut32 addr, const HexPkt *p);
RZ_API HexLoopAttr hex_get_loop_flag(const HexPkt *p);