// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

static inline bool is_last_instr(const ut8 parse_bits) {
	// Duplex instr. (parse bits = 0) are always the last.
	return ((parse_bits == 0x3) || (parse_bits == 0x0));
}

