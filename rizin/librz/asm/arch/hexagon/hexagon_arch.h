// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon
#ifndef HEXAGON_ARCH_H
#define HEXAGON_ARCH_H

#define MAX_CONST_EXT      512
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

extern HexState hexagon_state;

HexInsn *hex_get_instr_at_addr(const ut32 addr);
void hex_clear_pkt(HexPkt *p);
HexPkt *hex_get_stale_pkt();
HexPkt *hex_get_pkt(const ut32 addr);
void hex_insn_free(HexInsn *i);
ut32 hex_get_pkt_addr(const ut32 addr);
void hex_init_state();
HexInsn *hex_add_instr_to_state(const HexInsn *new_ins);
void hex_set_pkt_info(RZ_INOUT HexInsn *hi, const HexPkt *p, const ut8 k, const bool update_mnemonic);
void free_const_ext(HexConstExt *ce);
void hex_extend_op(RZ_INOUT HexOp *op, const bool set_new_extender, const ut32 addr);
void hexeagon_reverse_opcode(HexReversedOpcode *rz_reverse, const ut8 *buf, const ut64 addr);
HexInsn *get_new_instruction();
ut8 hexagon_get_pkt_index_of_addr(const ut32 addr, const HexPkt *p);
#endif
