// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

RZ_API int hexagon_v6_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	rz_return_val_if_fail(analysis && op && buf, -1);
	if (len < HEX_INSN_SIZE) {
		return -1;
	}
	if (analysis->pcalign == 0) {
		analysis->pcalign = HEX_PC_ALIGNMENT;
	}

	// Disassemble as many instructions as possible from the buffer.
	ut32 buf_offset = 0;
	while (buf_offset + HEX_INSN_SIZE <= len && buf_offset <= HEX_INSN_SIZE * HEX_MAX_INSN_PER_PKT) {
		const ut32 buf_ptr = rz_read_at_le32(buf, buf_offset);
		if (buf_offset > 0 && (buf_ptr == HEX_INVALID_INSN_0 || buf_ptr == HEX_INVALID_INSN_F)) {
			// Do not disassemble invalid instructions, if we already have a valid one.
			break;
		}

		HexReversedOpcode rev = { .action = HEXAGON_ANALYSIS, .ana_op = op, .asm_op = NULL };
		hexagon_reverse_opcode(NULL, &rev, buf + buf_offset, addr + buf_offset, false);
		buf_offset += HEX_INSN_SIZE;
	}
	// Copy operation actually requested.
	HexReversedOpcode rev = { .action = HEXAGON_ANALYSIS, .ana_op = op, .asm_op = NULL };
	hexagon_reverse_opcode(NULL, &rev, buf, addr, true);
	bool decoded_packet = len > HEX_INSN_SIZE;
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = hex_get_il_op(addr, decoded_packet);
	}

	return HEX_INSN_SIZE;
}

static RzAnalysisILConfig *rz_hexagon_il_config(RzAnalysis *a) {
	HexState *state = hexagon_state(true);
	state->just_init = true;
	return rz_analysis_il_config_new(32, a->big_endian, 32);
}
