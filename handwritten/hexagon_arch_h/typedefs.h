// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// The packet position indicators added to the instruction text.
typedef enum {
	SINGLE_IN_PKT,
	FIRST_IN_PKT,
	MID_IN_PKT,
	LAST_IN_PKT,
	ELOOP_0_PKT,
	ELOOP_1_PKT,
	ELOOP_01_PKT,
} HexPktSyntaxIndicator;

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
