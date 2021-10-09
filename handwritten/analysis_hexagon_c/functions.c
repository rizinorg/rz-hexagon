// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

static int hexagon_v6_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (analysis->pcalign == 0) {
		analysis->pcalign = 0x4;
	}

	HexReversedOpcode rev = { .action = HEXAGON_ANALYSIS, .ana_op = op, .asm_op = NULL };

	hexeagon_reverse_opcode(&rev, buf, addr);

	return op->size;
}
