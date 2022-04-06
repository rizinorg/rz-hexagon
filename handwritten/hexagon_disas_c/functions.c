// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

static inline bool is_last_instr(const ut8 parse_bits) {
	// Duplex instr. (parse bits = 0) are always the last.
	return ((parse_bits == 0x3) || (parse_bits == 0x0));
}

/**
 * \param masks array of exactly HEX_OP_MASKS_MAX items, ordered ascending by shift,
 *		optionally terminated earlier by an entry with bits = 0
 */
static ut32 hex_op_masks_extract(const HexOpMask *masks, ut32 val, RZ_OUT ut32 *bits_total) {
	ut8 off = 0;
	ut32 r = 0;
	for (size_t i = 0; i < HEX_OP_MASKS_MAX; i++) {
		const HexOpMask *m = &masks[i];
		if (!m->bits) {
			break;
		}
		r |= ((val >> m->shift) & rz_num_bitmask(m->bits)) << off;
		off += m->bits;
	}
	if (bits_total) {
		*bits_total = off;
	}
	return r;
}

/**
 * \return the index of the immediate operand used as the jump target or -1 if there is none.
 */
static int get_jmp_target_imm_op_index(const HexInsnTemplate *tpl) {
	if (!(tpl->flags & HEX_INSN_TEMPLATE_FLAG_HAS_JMP_TGT)) {
		return -1;
	}
	bool has_imm = false;
	size_t i;
	for (i = 0; i < HEX_MAX_OPERANDS; i++) {
		const HexOpTemplate *op = &tpl->ops[i];
		HexOpTemplateType type = op->info & HEX_OP_TEMPLATE_TYPE_MASK;
		if (type == HEX_OP_TEMPLATE_TYPE_NONE) {
			break;
		}
		if (type == HEX_OP_TEMPLATE_TYPE_IMM) {
			has_imm = true;
			if (op->info & HEX_OP_TEMPLATE_FLAG_IMM_PC_RELATIVE) {
				return i;
			}
		}
	}
	return has_imm && i == 1 ? 0 : -1;
}

static void hex_disasm_with_templates(const HexInsnTemplate *tpl, HexState *state, ut32 hi_u32, RZ_INOUT HexInsn *hi, ut64 addr, HexPkt *pkt) {
	bool print_reg_alias = rz_config_get_b(state->cfg, "plugins.hexagon.reg.alias");
	bool show_hash = rz_config_get_b(state->cfg, "plugins.hexagon.imm.hash");
	bool sign_nums = rz_config_get_b(state->cfg, "plugins.hexagon.imm.sign");
	char signed_imm[HEX_MAX_OPERANDS][32];
	// Find the right template
	for (; tpl->id; tpl++) {
		if ((hi_u32 & tpl->encoding.mask) == tpl->encoding.op) {
			break;
		}
	}
	if (!tpl->id) {
		// unknown/invalid
		return;
	}
	hi->instruction = tpl->id;
	hi->opcode = hi_u32;
	hi->parse_bits = (hi_u32 & HEX_PARSE_BITS_MASK) >> 14;
	hi->pred = tpl->pred;

	// textual disasm is built by copying tpl->syntax while inserting the ops at the right positions
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	size_t syntax_cur = 0;
	size_t syntax_len = strlen(tpl->syntax);

	hi->op_count = 0;
	for (size_t i = 0; i < HEX_MAX_OPERANDS; i++) {
		const HexOpTemplate *op = &tpl->ops[i];
		HexOpTemplateType type = op->info & HEX_OP_TEMPLATE_TYPE_MASK;
		if (type == HEX_OP_TEMPLATE_TYPE_NONE) {
			break;
		}

		if (op->syntax > syntax_cur && op->syntax <= syntax_len) {
			rz_strbuf_append_n(&sb, tpl->syntax + syntax_cur, op->syntax - syntax_cur);
			syntax_cur = op->syntax;
		}

		hi->op_count++;
		hi->ops[i].attr = 0;
		switch (type) {
		case HEX_OP_TEMPLATE_TYPE_IMM: {
			hi->ops[i].type = HEX_OP_TYPE_IMM;
			ut32 bits_total;
			hi->ops[i].op.imm = hex_op_masks_extract(op->masks, hi_u32, &bits_total) << op->imm_scale;
			hi->ops[i].shift = op->imm_scale;
			if (op->imm_scale) {
				hi->ops[i].attr |= HEX_OP_IMM_SCALED;
			}
			if (op->info & HEX_OP_TEMPLATE_FLAG_IMM_SIGNED) {
				ut32 shift = bits_total + op->imm_scale - 1;
				rz_warn_if_fail(shift < 64);
				if (hi->ops[i].op.imm & (1ull << shift)) {
					hi->ops[i].op.imm |= UT64_MAX << shift;
				}
			}
			if (op->info & HEX_OP_TEMPLATE_FLAG_IMM_EXTENDABLE) {
				hex_extend_op(state, &hi->ops[i], false, addr);
			}
			// textual disasm
			const char *h = show_hash ? ((op->info & HEX_OP_TEMPLATE_FLAG_IMM_DOUBLE_HASH) ? "##" : "#") : "";
			if (op->info & HEX_OP_TEMPLATE_FLAG_IMM_PC_RELATIVE) {
				rz_strbuf_appendf(&sb, "0x%" PFMT32x, pkt->pkt_addr + (st32)hi->ops[i].op.imm);
			} else if (op->info & HEX_OP_TEMPLATE_FLAG_IMM_SIGNED) {
				if (sign_nums && ((st32)hi->ops[i].op.imm) < 0) {
					char tmp[28] = {0};
					rz_hex_ut2st_str(hi->ops[i].op.imm, tmp, 28);
					snprintf(signed_imm[i], sizeof(signed_imm[i]), "%s%s", h, tmp);
				} else {
					snprintf(signed_imm[i], sizeof(signed_imm[i]), "%s0x%" PFMT32x, h, (st32)hi->ops[i].op.imm);
				}
				rz_strbuf_append(&sb, signed_imm[i]);
			} else {
				rz_strbuf_appendf(&sb, "%s0x%" PFMT32x, h, (ut32)hi->ops[i].op.imm);
			}
			break;
		}
		case HEX_OP_TEMPLATE_TYPE_IMM_CONST:
			hi->ops[i].type = HEX_OP_TYPE_IMM;
			hi->ops[i].op.imm = -1;
			// textual disasm
			rz_strbuf_append(&sb, "-1");
			break;
		case HEX_OP_TEMPLATE_TYPE_REG:
			hi->ops[i].type = HEX_OP_TYPE_REG;
			hi->ops[i].op.reg = hex_op_masks_extract(op->masks, hi_u32, NULL);
			if (op->info & HEX_OP_TEMPLATE_FLAG_REG_OUT) {
				hi->ops[i].attr |= HEX_OP_REG_OUT;
			}
			if (op->info & HEX_OP_TEMPLATE_FLAG_REG_PAIR) {
				hi->ops[i].attr |= HEX_OP_REG_PAIR;
			}
			if (op->info & HEX_OP_TEMPLATE_FLAG_REG_QUADRUPLE) {
				hi->ops[i].attr |= HEX_OP_REG_QUADRUPLE;
			}
			// textual disasm
			int regidx = hi->ops[i].op.reg;
			if (op->info & HEX_OP_TEMPLATE_FLAG_REG_N_REG) {
				regidx = resolve_n_register(hi->ops[i].op.reg, hi->addr, pkt);
			}
			rz_strbuf_append(&sb, hex_get_reg_in_class(op->reg_cls, regidx, print_reg_alias));
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}

	// Textual disassembly
	if (syntax_len > syntax_cur) {
		rz_strbuf_append_n(&sb, tpl->syntax + syntax_cur, syntax_len - syntax_cur);
	}
	strncpy(hi->mnem_infix, rz_strbuf_get(&sb), sizeof(hi->mnem_infix) - 1);
	snprintf(hi->mnem, sizeof(hi->mnem), "%s%s%s", hi->pkt_info.mnem_prefix, hi->mnem_infix, hi->pkt_info.mnem_postfix);

	// RzAnalysisOp contents
	hi->ana_op.addr = hi->addr;
	hi->ana_op.id = hi->instruction;
	hi->ana_op.size = 4;
	hi->ana_op.cond = tpl->cond;
	hi->ana_op.type = hi->ana_op.prefix == RZ_ANALYSIS_OP_PREFIX_HWLOOP_END ? RZ_ANALYSIS_OP_TYPE_CJMP : tpl->type;
	int jmp_target_imm_op_index = get_jmp_target_imm_op_index(tpl);
	if (jmp_target_imm_op_index >= 0) {
		if (!(tpl->flags & HEX_INSN_TEMPLATE_FLAG_CALL) && !(tpl->flags & HEX_INSN_TEMPLATE_FLAG_PREDICATED)) {
			pkt->is_eob = true;
		}
		hi->ana_op.jump = pkt->pkt_addr + (st32)hi->ops[jmp_target_imm_op_index].op.imm;
		if (tpl->flags & HEX_INSN_TEMPLATE_FLAG_PREDICATED) {
			hi->ana_op.fail = hi->ana_op.addr + 4;
		}
		if (tpl->flags & HEX_INSN_TEMPLATE_FLAG_LOOP_BEGIN) {
			if (tpl->flags & HEX_INSN_TEMPLATE_FLAG_LOOP_0) {
				pkt->hw_loop0_addr = hi->ana_op.jump;
			} else if (tpl->flags & HEX_INSN_TEMPLATE_FLAG_LOOP_1) {
				pkt->hw_loop1_addr = hi->ana_op.jump;
			}
		}
	}
	for (size_t i = 0; i < RZ_MIN(hi->op_count, RZ_ARRAY_SIZE(hi->ana_op.analysis_vals)); i++) {
		const HexOpTemplate *op = &tpl->ops[i];
		HexOpTemplateType type = op->info & HEX_OP_TEMPLATE_TYPE_MASK;
		if (jmp_target_imm_op_index >= 0 && type == HEX_OP_TEMPLATE_TYPE_IMM) {
			hi->ana_op.val = hi->ana_op.jump;
			hi->ana_op.analysis_vals[i].imm = hi->ana_op.jump;
		} else if (tpl->id == HEX_INS_J2_JUMPR) {
			// jumpr Rs is sometimes used as jumpr R31.
			// Block analysis needs to check it to recognize if this jump is a return.
			hi->ana_op.analysis_vals[0].plugin_specific = hi->ops[0].op.reg;
		} else if (type == HEX_OP_TEMPLATE_TYPE_IMM) {
			hi->ana_op.analysis_vals[i].imm = hi->ops[i].op.imm;
		}
	}

	if (tpl->id == HEX_INS_A4_EXT) {
		hex_extend_op(state, &(hi->ops[0]), true, addr);
	}
}

int hexagon_disasm_instruction(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, HexPkt *pkt) {
	ut32 addr = hi->addr;
	if (hi->pkt_info.last_insn) {
		switch (hex_get_loop_flag(pkt)) {
		default: break;
		case HEX_LOOP_01:
			hi->ana_op.prefix = RZ_ANALYSIS_OP_PREFIX_HWLOOP_END;
			hi->ana_op.fail = pkt->hw_loop0_addr;
			hi->ana_op.jump = pkt->hw_loop1_addr;
			hi->ana_op.val = hi->ana_op.jump;
			break;
		case HEX_LOOP_0:
			hi->ana_op.prefix = RZ_ANALYSIS_OP_PREFIX_HWLOOP_END;
			hi->ana_op.jump = pkt->hw_loop0_addr;
			hi->ana_op.val = hi->ana_op.jump;
			break;
		case HEX_LOOP_1:
			hi->ana_op.prefix = RZ_ANALYSIS_OP_PREFIX_HWLOOP_END;
			hi->ana_op.jump = pkt->hw_loop1_addr;
			hi->ana_op.val = hi->ana_op.jump;
			break;
		}
	}
	if (hi_u32 != 0x00000000) {
		if (((hi_u32 >> 14) & 0x3) == 0) {
			// DUPLEXES
			ut32 cat = (((hi_u32 >> 29) & 0xF) << 1) | ((hi_u32 >> 13) & 1);
			if (cat < 0xf) {
				hex_disasm_with_templates(templates_duplex[cat], state, hi_u32, hi, addr, pkt);
				hi->duplex = true;
			}
		} else {
			ut32 cat = (hi_u32 >> 28) & 0xF;
			hex_disasm_with_templates(templates_normal[cat], state, hi_u32, hi, addr, pkt);
		}
	}
	if (pkt->is_eob && is_last_instr(hi->parse_bits)) {
		hi->ana_op.eob = true;
	}
	if (hi->instruction == HEX_INS_INVALID_DECODE) {
		hi->parse_bits = ((hi_u32)&0xc000) >> 14;
		hi->ana_op.type = RZ_ANALYSIS_OP_TYPE_ILL;
		sprintf(hi->mnem_infix, "invalid");
		sprintf(hi->mnem, "%s%s%s", hi->pkt_info.mnem_prefix, hi->mnem_infix, hi->pkt_info.mnem_postfix);
	}
	return 4;
}
