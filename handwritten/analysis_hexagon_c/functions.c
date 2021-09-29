// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

static int hexagon_v6_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	static ut32 prev_addr = UT32_MAX;
	static ut32 pkt_addr = 0;

	if (analysis->pcalign == 0) {
		analysis->pcalign = 0x4;
	}

	HexInsn hi = { 0 };
	ut32 data = 0;
	data = rz_read_le32(buf);
	int size = hexagon_disasm_instruction(data, &hi, (ut32)addr, prev_addr);
	op->size = size;
	if (size <= 0) {
		return size;
	}

	if (hi.pkt_info.first_insn) {
		pkt_addr = addr;
	}

	hi.pkt_info.pkt_addr = pkt_addr;
	op->addr = addr;
	op->jump = op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	prev_addr = (ut32) addr;
	return hexagon_analysis_instruction(&hi, op);
}
