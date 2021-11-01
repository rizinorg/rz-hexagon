// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// The type of opcode reversing which is be done on the opcode.
typedef enum {
	HEXAGON_ANALYSIS,
	HEXAGON_DISAS,
} HexReverseAction;

/**
 * \brief Pointer to the rizin structs for disassembled and analysed instructions.
 * 
 */
typedef struct {
    HexReverseAction action; // Whether ana_op, asm_op or both should be filled.
	RzAnalysisOp *ana_op;
	RzAsmOp *asm_op;
} HexReversedOpcode;
