// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
//
// SPDX-License-Identifier: LGPL-3.0-only

//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "hexagon.h"
#include "hexagon_insn.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int l) {
	static ut32 prev_addr = UT32_MAX;
	HexInsn hi = { 0 };
	hi.instruction = HEX_INS_INVALID_DECODE;
	ut32 data = rz_read_le32(buf);
	ut32 addr = (ut32)a->pc;
	op->buf_asm.len = hexagon_disasm_instruction(data, &hi, addr, prev_addr);
	rz_strbuf_set(&op->buf_asm, hi.mnem);
	prev_addr = addr;
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
