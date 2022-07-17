// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define MAX_CONST_EXT 512
#define HEXAGON_STATE_PKTS 8

typedef enum {
	HEX_OP_TYPE_IMM,
	HEX_OP_TYPE_REG,
} HexOpType;

typedef enum {
	HEX_OP_CONST_EXT = 1 << 0, // Constant extender marker for Immediate
	HEX_OP_REG_HI = 1 << 1, // Rn.H marker
	HEX_OP_REG_LO = 1 << 2, // Rn.L marker
	HEX_OP_REG_PAIR = 1 << 3, // Is this a register pair?
	HEX_OP_REG_QUADRUPLE = 1 << 4, // Is it a register with 4 sub registers?
	HEX_OP_REG_OUT = 1 << 5, // Is the register the destination register?
	HEX_OP_IMM_SCALED = 1 << 6 // Is the immediate shifted?
} HexOpAttr;

typedef enum {
	HEX_NO_LOOP = 0,
	HEX_LOOP_0 = 1, // Is packet of loop0
	HEX_LOOP_1 = 1 << 1, // Is packet of loop1
	HEX_LOOP_01 = 1 << 2 // Belongs to loop 0 and 1
} HexLoopAttr;

typedef struct {
	bool first_insn;
	bool last_insn;
	char mnem_prefix[16]; // Package indicator
	char mnem_postfix[24]; // for ":endloop" string.
} HexPktInfo;

typedef struct {
	ut8 type;
	union {
		ut8 reg; // + additional Hi or Lo selector // + additional shift // + additional :brev //
		st64 imm;
	} op;
	HexOpAttr attr;
	ut8 shift;
} HexOp;

typedef struct {
	bool is_sub; ///< Flag for sub-instructions.
	ut8 op_count; ///< The number of operands this instruction has.
	ut32 addr; ///< Memory address the instruction is located (high sub-instruction is unaligned by 2 byte!).
	ut32 opcode; ///< The instruction opcode.
	HexInsnID instruction; ///< The instruction identifier
	char text_infix[128]; ///< Textual disassembly of the instruction.
	HexOp ops[HEX_MAX_OPERANDS]; ///< The operands of the instructions.
} HexInsn;

/**
 * \brief The instruction container holds one instruction or two sub-instructions if it is a duplex.
 * It stores meta information about those instruction(s) like opcode, packet information or the parse bits.
 */
typedef struct {
	ut8 parse_bits; ///< Parse bits of instruction.
    bool is_duplex; ///< DOes this container hold two sub-instructions?
    ut32 identifier; ///< Equals instruction ID if is_duplex = false. Otherwise: (low.id << 16) | (high.id << 0)
    union {
        HexInsn *sub[2]; ///< Pointer to sub-instructions if is_duplex = true. sub[0] = low, sub[1] = high
        HexInsn *insn; ///< Pointer to instruction if is_duplex = false.
    } bin;
    ut32 addr; ///< Address of container. Equals address of instruction or of the low sub-instruction if this is a duplex.
    ut32 opcode; ///< The instruction opcode.
    HexPktInfo pkt_info; ///< Packet related information. First/last instr., prefix and postfix for mnemonic etc.
    RzAsmOp asm_op; ///< Private copy of AsmOp. Currently only of interest because it holds the utf8 flag.
	RzAnalysisOp ana_op; ///< Private copy of AnalysisOp. Analysis info is written into it.
	char text[192]; ///< Textual disassembly
} HexInsnContainer;

typedef struct {
	RzList /* HexInsnContainer */ *bin; ///< List of instruction containers.
	bool last_instr_present; ///< Has an instruction the parsing bits 0b11 set (is last instruction).
	bool is_valid; ///< Is it a valid packet? Do we know which instruction is the first?
	ut32 hw_loop0_addr; ///< Start address of hardware loop 0
	ut32 hw_loop1_addr; ///< Start address of hardware loop 1
	ut64 last_access; ///< Last time accessed in milliseconds
	ut32 pkt_addr; ///< Address of the packet. Equals the address of the first instruction.
	bool is_eob; ///< Is this packet the end of a code block? E.g. contains unconditional jmp.
} HexPkt;

typedef struct {
	ut32 addr; // Address of the instruction which gets the extender applied.
	ut32 const_ext; // The constant extender value.
} HexConstExt;

/**
 * \brief Buffer packets for reversed instructions.
 * 
 */
typedef struct {
    HexPkt pkts[HEXAGON_STATE_PKTS]; // buffered instructions
    RzList *const_ext_l; // Constant extender values.
	RzAsm rz_asm; // Copy of RzAsm struct. Holds certain flags of interesed for disassembly formatting.
	RzConfig *cfg;
	RzPVector /* RzAsmTokenPattern* */ *token_patterns; ///< PVector with token patterns. Priority ordered.
} HexState;
