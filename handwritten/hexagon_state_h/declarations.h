// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

extern HexState hexagon_state;

ut8 hex_find_stale_state_pkt_i();
void hex_clear_pkt(const ut8 pkt_index);
HexInsn *hex_get_instr_at_addr(const ut32 addr);
void hex_add_instr_to_state(const HexInsn *instr);