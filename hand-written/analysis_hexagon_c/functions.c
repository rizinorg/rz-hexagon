// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

RZ_API int hexagon_v6_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	rz_return_val_if_fail(analysis && op && buf, -1);
	if (len < 4) {
		return -1;
	}
	if (analysis->pcalign == 0) {
		analysis->pcalign = 0x4;
	}

	HexReversedOpcode rev = { .action = HEXAGON_ANALYSIS, .ana_op = op, .asm_op = NULL };

	hexagon_reverse_opcode(NULL, &rev, buf, addr);

	return op->size;
}
