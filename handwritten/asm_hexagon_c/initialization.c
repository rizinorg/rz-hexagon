// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int l) {
	ut32 addr = (ut32) a->pc;
	HexReversedOpcode rev = { .action = HEXAGON_DISAS, .ana_op = NULL, .asm_op = op };

	hexeagon_reverse_opcode(&rev, buf, addr);

	return op->size;
}

RzAsmPlugin rz_asm_plugin_hexagon = {
	.name = "hexagon",
	.arch = "hexagon",
	.author = "xvilka",
	.license = "LGPL3",
	.bits = 32,
	.desc = "Qualcomm Hexagon (QDSP6) V6",
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_hexagon
};
#endif
