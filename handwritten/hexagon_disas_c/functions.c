// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

static inline bool is_endloop01_instr(const HexInsn *hi, const HexPkt *p) {
	return ((p->loop_attr & HEX_ENDS_LOOP_0) && (p->loop_attr & HEX_ENDS_LOOP_1) && hi->pkt_info.last_insn);
}

static inline bool is_endloop0_instr(const HexInsn *hi, const HexPkt *p) {
	return ((p->loop_attr & HEX_ENDS_LOOP_0) && hi->pkt_info.last_insn);
}

static inline bool is_endloop1_instr(const HexInsn *hi, const HexPkt *p) {
	return ((p->loop_attr & HEX_ENDS_LOOP_1) && hi->pkt_info.last_insn);
}

static inline bool is_loop0_begin(const HexInsn *hi) {
	return ((hi->pkt_info.loop_attr & HEX_LOOP_0) && !(hi->pkt_info.loop_attr & (HEX_ENDS_LOOP_0 | HEX_ENDS_LOOP_1)));
}

static inline bool is_loop1_begin(const HexInsn *hi) {
	return ((hi->pkt_info.loop_attr & HEX_LOOP_1) && !(hi->pkt_info.loop_attr & (HEX_ENDS_LOOP_0 | HEX_ENDS_LOOP_1)));
}
