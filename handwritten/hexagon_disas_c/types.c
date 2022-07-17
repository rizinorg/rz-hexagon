// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#define HEX_OP_MASKS_MAX 4

typedef enum {
	HEX_OP_TEMPLATE_TYPE_NONE = 0,
	HEX_OP_TEMPLATE_TYPE_IMM = 1,
	HEX_OP_TEMPLATE_TYPE_IMM_CONST = 2,
	HEX_OP_TEMPLATE_TYPE_REG = 3,
	HEX_OP_TEMPLATE_TYPE_MASK = 3
} HexOpTemplateType;

typedef enum {
	// 1 << 0 and 1 << 1 reserved by HexOpTemplateType
	// for HEX_OP_TEMPLATE_TYPE_REG:
	HEX_OP_TEMPLATE_FLAG_REG_OUT = 1 << 2,
	HEX_OP_TEMPLATE_FLAG_REG_PAIR = 1 << 3,
	HEX_OP_TEMPLATE_FLAG_REG_QUADRUPLE = 1 << 4,
	HEX_OP_TEMPLATE_FLAG_REG_N_REG = 1 << 5,
	// for HEX_OP_TEMPLATE_TYPE_IMM:
	HEX_OP_TEMPLATE_FLAG_IMM_SIGNED = 1 << 2,
	HEX_OP_TEMPLATE_FLAG_IMM_EXTENDABLE = 1 << 3,
	HEX_OP_TEMPLATE_FLAG_IMM_PC_RELATIVE = 1 << 4,
	HEX_OP_TEMPLATE_FLAG_IMM_DOUBLE_HASH = 1 << 5
} HexOpTemplateFlag;

// Note:
// The structs below are using ut8 instead of direct enum types
// where possible to optimize for size. Members are also ordered
// deliberately to make them well packed.
// Keep this in mind when changing anything here!

typedef struct {
	ut8 bits; // number of bits this part has
	ut8 shift; // index of the first bit in the instruction where this part starts
} HexOpMask;

typedef struct {
	ut8 info; // HexOpTemplateType | HexOpTemplateFlag
	ut8 syntax; // offset into HexInsnTemplate.syntax where to insert this op
	HexOpMask masks[HEX_OP_MASKS_MAX];
	union {
		ut8 imm_scale;
		ut8 reg_cls; // HexRegClass
	};
} HexOpTemplate;

typedef enum {
	HEX_INSN_TEMPLATE_FLAG_CALL = 1 << 0,
	HEX_INSN_TEMPLATE_FLAG_PREDICATED = 1 << 1,
	HEX_INSN_TEMPLATE_FLAG_HAS_JMP_TGT = 1 << 2,
	HEX_INSN_TEMPLATE_FLAG_LOOP_BEGIN = 1 << 3,
	HEX_INSN_TEMPLATE_FLAG_LOOP_0 = 1 << 4,
	HEX_INSN_TEMPLATE_FLAG_LOOP_1 = 1 << 5
} HexInsnTemplateFlag;

typedef struct {
	struct {
		ut32 mask;
		ut32 op;
	} encoding;
	HexInsnID id;
	HexOpTemplate ops[HEX_MAX_OPERANDS];
	ut8 pred; // HexPred
	ut8 cond; // RzTypeCond
	ut8 flags; // HexInsnTemplateFlag
	const char *syntax;
	_RzAnalysisOpType type;
} HexInsnTemplate;
