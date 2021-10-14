// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define MAX_CONST_EXT 512
#define HEXAGON_STATE_PKTS 8

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

/**
 * \brief Buffer packets for reversed instructions.
 * 
 */
typedef struct {
    HexPkt pkts[HEXAGON_STATE_PKTS]; // buffered instructions
    RzList *const_ext_l; // Constant extender values.
} HexState;
