// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define HEX_PKT_UNK  "?   "
#define HEX_PKT_SINGLE "[   "
#define HEX_PKT_SINGLE_UTF8   "[   "
#define HEX_PKT_FIRST_UTF8 "┌   "
#define HEX_PKT_MID_UTF8   "│   "
#define HEX_PKT_LAST_UTF8  "└   "
#define HEX_PKT_FIRST_SDK "{   "
#define HEX_PKT_SDK_PADDING   "    "
#define HEX_PKT_LAST_SDK " }"
#define HEX_PKT_FIRST "/   "
#define HEX_PKT_MID   "|   "
#define HEX_PKT_LAST  "\\   "
#define HEX_PKT_ELOOP_01_UTF8 "     ∎ endloop01"
#define HEX_PKT_ELOOP_1_UTF8 "     ∎ endloop1"
#define HEX_PKT_ELOOP_0_UTF8 "     ∎ endloop0"
#define HEX_PKT_ELOOP_01 "     < endloop01"
#define HEX_PKT_ELOOP_1 "     < endloop1"
#define HEX_PKT_ELOOP_0 "     < endloop0"
#define HEX_PKT_ELOOP_01_SDK ":endloop01"
#define HEX_PKT_ELOOP_1_SDK ":endloop1"
#define HEX_PKT_ELOOP_0_SDK ":endloop0"

RZ_API HexInsn *hexagon_alloc_instr();
RZ_API void hex_insn_free(RZ_NULLABLE HexInsn *i);
RZ_API HexInsnContainer *hexagon_alloc_instr_container();
RZ_API void hex_insn_container_free(RZ_NULLABLE HexInsnContainer *c);
RZ_API void hex_const_ext_free(RZ_NULLABLE HexConstExt *ce);
RZ_API HexState *hexagon_state(bool reset);
RZ_IPI void hexagon_state_fini(HexState *state);
RZ_API void hexagon_reverse_opcode(const RzAsm *rz_asm, HexReversedOpcode *rz_reverse, const ut8 *buf, const ut64 addr, const bool copy_result);
RZ_API ut8 hexagon_get_pkt_index_of_addr(const ut32 addr, const HexPkt *p);
RZ_API HexLoopAttr hex_get_loop_flag(const HexPkt *p);
RZ_API const HexOp *hex_isa_to_reg(const HexInsn *hi, const char isa_id, bool new_reg);
RZ_API ut64 hex_isa_to_imm(const HexInsn *hi, const char isa_id);
void hex_set_hic_text(RZ_INOUT HexInsnContainer *hic);
RZ_API void hex_move_insn_container(RZ_OUT HexInsnContainer *dest, const HexInsnContainer *src);
RZ_API HexPkt *hex_get_pkt(RZ_BORROW HexState *state, const ut32 addr);
RZ_API HexInsnContainer *hex_get_hic_at_addr(HexState *state, const ut32 addr);
RZ_API const HexOp hex_nreg_to_op(const HexInsnPktBundle *bundle, const char isa_id);
