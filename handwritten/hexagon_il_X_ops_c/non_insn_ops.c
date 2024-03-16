// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \brief Returns the value of an register field property.
 *
 * \param property The property to get the value for.
 * \param field The register field.
 * \return RzILOpPure The value as integer as U32 or U32_MAX on failure.
 */
RZ_IPI RZ_OWN RzILOpPure *hex_get_rf_property_val(const HexRegFieldProperty property, const HexRegField field) {
	RzILOpPure *r = NULL;
	switch (field) {
	default:
		RZ_LOG_WARN("Register field not implemented.\n");
		break;
	case HEX_REG_FIELD_USR_LPCFG:
		if (property == HEX_RF_WIDTH) {
			r = U32(2);
		} else if (property == HEX_RF_OFFSET) {
			r = U32(8);
		}
		break;
	case HEX_REG_FIELD_USR_OVF:
		if (property == HEX_RF_WIDTH) {
			r = U32(1);
		} else if (property == HEX_RF_OFFSET) {
			r = U32(0);
		}
		break;
	}
	return r;
}

/**
 * \brief Returns the next PC as pure.
 *
 * \param pkt The instruction packet.
 * \return RzILOpPure* The next PC as pure.
 */
RZ_IPI RZ_OWN RzILOpEffect *hex_get_npc(const HexPkt *pkt) {
	rz_return_val_if_fail(pkt, NULL);
	RzILOpPure *r;
	r = U64(pkt->pkt_addr + (rz_list_length(pkt->bin) * HEX_INSN_SIZE));
	return SETL("ret_val", r);
}

RZ_IPI RZ_OWN RzILOpEffect *hex_commit_packet(HexInsnPktBundle *bundle) {
	HexILExecData *stats = &bundle->pkt->il_op_stats;
	RzILOpEffect *commit_seq = EMPTY();
	for (ut8 i = 0; i <= HEX_REG_CTR_REGS_C31; ++i) {
		if (!(rz_bv_get(stats->ctr_written, i))) {
			continue;
		}
		const char *dest_reg = hex_get_reg_in_class(HEX_REG_CLASS_CTR_REGS, i, false, false, false);
		const char *src_reg = hex_get_reg_in_class(HEX_REG_CLASS_CTR_REGS, i, false, true, false);
		commit_seq = SEQ2(commit_seq, SETG(dest_reg, VARG(src_reg)));
	}

	for (ut8 i = 0; i <= HEX_REG_INT_REGS_R31; ++i) {
		if (!(rz_bv_get(stats->gpr_written, i))) {
			continue;
		}
		const char *dest_reg = hex_get_reg_in_class(HEX_REG_CLASS_INT_REGS, i, false, false, false);
		const char *src_reg = hex_get_reg_in_class(HEX_REG_CLASS_INT_REGS, i, false, true, false);
		commit_seq = SEQ2(commit_seq, SETG(dest_reg, VARG(src_reg)));
	}

	for (ut8 i = 0; i <= HEX_REG_PRED_REGS_P3; ++i) {
		if (!(rz_bv_get(stats->pred_written, i))) {
			continue;
		}
		const char *dest_reg = hex_get_reg_in_class(HEX_REG_CLASS_PRED_REGS, i, false, false, false);
		const char *src_reg = hex_get_reg_in_class(HEX_REG_CLASS_PRED_REGS, i, false, true, false);
		commit_seq = SEQ2(commit_seq, SETG(dest_reg, VARG(src_reg)));
	}

	hex_reset_il_pkt_stats(stats);
	return commit_seq;
}

RZ_IPI RZ_OWN RzILOpEffect *hex_il_op_jump_flag_init(HexInsnPktBundle *bundle) {
	return SETL("jump_flag", IL_FALSE);
}

RZ_IPI RZ_OWN RzILOpEffect *hex_il_op_next_pkt_jmp(HexInsnPktBundle *bundle) {
	return BRANCH(VARL("jump_flag"), JMP(VARL("jump_target")), JMP(U32(bundle->pkt->pkt_addr + (HEX_INSN_SIZE * rz_list_length(bundle->pkt->bin)))));
}
