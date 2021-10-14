// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \brief Resolves the 3 bit value of an Nt.new reg to the general register of the producer. 
 * 
 * \param addr The address of the current instruction.
 * \param reg_num Bits of Nt.new reg.
 * \param p The current packet.
 * \return int The number of the general register. Or UT32_MAX if any error occured.
 */
int resolve_n_register(const int reg_num, const ut32 addr, const HexPkt *p) {
	// .new values are documented in Programmers Reference Manual
	if (reg_num <= 1 || reg_num >= 8) {
		return UT32_MAX;
	}

	ut8 ahead = (reg_num >> 1);
	ut8 i = hexagon_get_pkt_index_of_addr(addr, p);
	if (i == UT8_MAX) {
		return UT32_MAX;
	}

	ut8 prod_i = i; // Producer index
	HexInsn *hi;
	RzListIter *it;
	rz_list_foreach_prev(p->insn, it, hi) {
		if (ahead == 0) {
			break;
		}
		if (hi->addr < addr) {
			if (hi->instruction == HEX_INS_A4_EXT) {
				--prod_i;
				continue;
			}
			--ahead;
			--prod_i;
		}
	}

	hi = rz_list_get_n(p->insn, prod_i);

	if (!hi) {
		return UT32_MAX;
	}
	if (hi->instruction == HEX_INS_A4_EXT) {
		return UT32_MAX;
	}

	for (ut8 i = 0; i < 6; ++i) {
		if (hi->ops[i].attr & HEX_OP_REG_OUT) {
			return hi->ops[i].op.reg;
		}
	}
	return UT32_MAX;
}
