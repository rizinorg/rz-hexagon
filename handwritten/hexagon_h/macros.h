// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define HEX_INSN_SIZE        4
#define HEX_MAX_INSN_PER_PKT 4

#define HEX_PC_ALIGNMENT 0x4

#define HEX_PRED_WIDTH  8
#define HEX_GPR_WIDTH   32
#define HEX_GPR64_WIDTH 64
#define HEX_CTR_WIDTH   32
#define HEX_CTR64_WIDTH 64

#define HEX_INVALID_INSN_0 0x00000000
#define HEX_INVALID_INSN_F 0xffffffff

#define MAX_CONST_EXT      512
#define HEXAGON_STATE_PKTS 8
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#define ALIAS2OP(alias, is_new) hex_alias_to_op(alias, is_new)
#define EXPLICIT2OP(num, class, is_new) hex_explicit_to_op(num, class, is_new)
#define NREG2OP(bundle, isa_id) hex_nreg_to_op(bundle, isa_id)