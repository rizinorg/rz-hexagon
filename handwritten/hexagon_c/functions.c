// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \brief Resolves the 3 bit value of an Nt.new reg to the general register of the producer.
 *
 * \param addr The address of the current instruction.
 * \param reg_num Bits of Nt.new reg.
 * \param p The current packet.
 * \return int The number of the general register. Or UT32_MAX if any error occurred.
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
	HexInsnContainer *hic;
	RzListIter *it;
	rz_list_foreach_prev(p->bin, it, hic) {
		if (ahead == 0) {
			break;
		}
		if (hic->addr < addr) {
			if (hic->identifier == HEX_INS_A4_EXT) {
				--prod_i;
				continue;
			}
			--ahead;
			--prod_i;
		}
	}

	hic = rz_list_get_n(p->bin, prod_i);

	if (!hic || !hic->bin.insn || (hic->is_duplex && (!hic->bin.sub[0] || !hic->bin.sub[1]))) {
		// This case happens if the current instruction (with the .new register)
		// is yet the only one in the packet.
		return UT32_MAX;
	}
	if (hic->identifier == HEX_INS_A4_EXT) {
		return UT32_MAX;
	}
	HexInsn *hi = !hic->is_duplex ? hic->bin.insn : (hic->bin.sub[0]->addr == addr ? hic->bin.sub[0] : hic->bin.sub[1]);
	for (ut8 k = 0; k < hi->op_count; ++k) {
		if (hi->ops[k].attr & HEX_OP_REG_OUT) {
			return hi->ops[k].op.reg;
		}
	}
	return UT32_MAX;
}

/**
 * \brief Returns a HexOp of the given register number and class.
 *
 * \param reg_num The register number as in the name.
 * \param reg_class The HexRegClass this register belongs to.
 * \param tmp_reg Flag if the register is a .new register.
 *
 * \return A setup HexOp. Currently the HexOp.attr field is *not* set!
 */
RZ_API const HexOp hex_explicit_to_op(ut32 reg_num, HexRegClass reg_class, bool tmp_reg) {
	HexOp op = { 0 };
	op.type = HEX_OP_TYPE_REG;
	op.class = reg_class;
	op.op.reg = reg_num;
	// TODO: Add attributes?
	return op;
}

/**
 * \brief Returns a HexOp of the given register alias.
 *
 * \param alias The alias to get the HexOp for.
 * \param tmp_reg Flag if the alias is referring to the .new register.
 *
 * \return A setup HexOp. Currently the HexOp.attr field is *not* set!
 */
RZ_API const HexOp hex_alias_to_op(HexRegAlias alias, bool tmp_reg) {
	HexOp op = { 0 };
	if (alias >= ARRAY_LEN(hex_alias_reg_lt_v69)) {
		rz_warn_if_reached();
		return op;
	}
	op.type = HEX_OP_TYPE_REG;
	op.class = hex_alias_reg_lt_v69[alias].cls;
	op.op.reg = hex_alias_reg_lt_v69[alias].reg_enum;
	// TODO: Add attributes?
	return op;
}

/**
 * \brief Returns the real register name for a register alias.
 *
 * \param alias The register alias.
 * \param tmp_reg The register the tmp real register name.
 * \return const char * The corresponding register name. Or NULL on error.
 */
RZ_API const char *hex_alias_to_reg(HexRegAlias alias, bool tmp_reg) {
	if (alias >= ARRAY_LEN(hex_alias_reg_lt_v69)) {
		return NULL;
	}
	HexRegClass reg_class = hex_alias_reg_lt_v69[alias].cls;
	int reg_enum = hex_alias_reg_lt_v69[alias].reg_enum;
	if (alias == HEX_REG_ALIAS_PC) {
		return "PC";
	}
	return hex_get_reg_in_class(reg_class, reg_enum, false, tmp_reg, true);
}
