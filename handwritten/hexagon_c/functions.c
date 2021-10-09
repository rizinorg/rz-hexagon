// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

int resolve_n_register(const int reg_num, const HexPkt *p) {
	if (!p->is_valid || reg_num == 0 || reg_num >= 8) {
		return UT32_MAX;
	}
	// (reg_num >> 1) is the instruction index whichs out operand is the new value.
	// In this plugin the last instruction in a packet is located at the higher index.
	// Hexagon seems to place it at index 0.
	// Switch indices.
	ut8 i_pos = rz_list_length(p->insn) - 1 - (reg_num >> 1);
	HexInsn *instr = rz_list_get_n(p->insn, i_pos);

	if (!instr) {
		RZ_LOG_WARN("Did not find .new register in packet @ 0x%x\n", p->pkt_addr);
		return UT32_MAX;
	}
	for (ut8 i = 0; i < 6; ++i) {
		if (instr->ops[i].attr & HEX_OP_REG_OUT) {
			return instr->ops[i].op.reg;
		}
	}
	return UT32_MAX;
}
