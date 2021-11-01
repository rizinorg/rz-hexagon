// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

HexInsn *hex_get_instr_at_addr(HexState *state, const ut32 addr);
void hex_clear_pkt(HexPkt *p);
HexPkt *hex_get_stale_pkt(HexState *state);
HexPkt *hex_get_pkt(HexState *state, const ut32 addr);
void hex_insn_free(HexInsn *i);
ut32 hex_get_pkt_addr(HexState *state, const ut32 addr);
bool hex_plugin_init();
bool hex_plugin_fini();
HexState *hex_state(bool destruct);
HexInsn *hex_add_instr_to_state(HexState *state, const HexInsn *new_ins);
void hex_set_pkt_info(RZ_INOUT HexInsn *hi, const HexPkt *p, const ut8 k, const bool update_mnemonic);
void free_const_ext(HexConstExt *ce);
void hexagon_reverse_opcode(HexReversedOpcode *rz_reverse, const ut8 *buf, const ut64 addr);
HexInsn *get_new_instruction();
ut8 hexagon_get_pkt_index_of_addr(const ut32 addr, const HexPkt *p);
