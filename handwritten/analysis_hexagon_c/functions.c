// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
//
// SPDX-License-Identifier: LGPL-3.0-only

static int hexagon_v6_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	HexInsn hi = {0};;
	ut32 data = 0;
	memset (op, 0, sizeof (RzAnalysisOp));
	data = rz_read_le32 (buf);
	int size = hexagon_disasm_instruction (data, &hi, (ut32) addr);
	op->size = size;
	if (size <= 0) {
		return size;
	}

	op->addr = addr;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;
	return hexagon_analysis_instruction (&hi, op);
}
