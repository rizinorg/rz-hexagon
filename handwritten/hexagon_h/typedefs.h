// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define MAX_CONST_EXT 512
#define HEXAGON_STATE_PKTS 8

// Predicates - declare the predicate state
typedef enum {
	HEX_NOPRED, // no conditional execution
	HEX_PRED_TRUE, // if (Pd) ...
	HEX_PRED_FALSE, // if (!Pd) ...
	HEX_PRED_NEW, // if (Pd.new) or if (!Pd.new)
} HexPred;

// TODO NOT IN USE
// Pre/post-fixes, different types
typedef enum {
	HEX_PF_RND = 1, // :rnd
	HEX_PF_CRND = 1 << 1, // :crnd
	HEX_PF_RAW = 1 << 2, // :raw
	HEX_PF_CHOP = 1 << 3, // :chop
	HEX_PF_SAT = 1 << 4, // :sat
	HEX_PF_HI = 1 << 5, // :hi
	HEX_PF_LO = 1 << 6, // :lo
	HEX_PF_LSH1 = 1 << 7, // :<<1
	HEX_PF_LSH16 = 1 << 8, // :<<16
	HEX_PF_RSH1 = 1 << 9, // :>>1
	HEX_PF_NEG = 1 << 10, // :neg
	HEX_PF_POS = 1 << 11, // :pos
	HEX_PF_SCALE = 1 << 12, // :scale, for FMA instructions
	HEX_PF_DEPRECATED = 1 << 15, // :deprecated
} HexPf;

typedef enum {
	HEX_OP_TYPE_IMM,
	HEX_OP_TYPE_REG,
	// TODO It might be useful to differ between control, HVX, guest regs etc. Also see HexOp
} HexOpType;

// Attributes - .H/.L, const extender
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
	ut32 opcode;
	ut8 parse_bits;
	int instruction;
	ut32 mask;
	HexPred pred; // Predicate type
	bool duplex; // is part of duplex container?
	bool compound; // is part of compound instruction?
	int shift; // Optional shift left is it true?
	HexPktInfo pkt_info; // Packet related information. First/last instr., prefix and postfix for mnemonic etc.
	ut8 op_count;
	HexOp ops[6];
	char mnem_infix[128]; // The mnemonic without the pre- and postfix.
	char mnem[192]; // Instruction mnemonic
	ut32 addr; // Memory address the instruction is located.
	RzAsmOp asm_op;
	RzAnalysisOp ana_op;
} HexInsn;

typedef struct {
	RzList *insn; // List of instructions.
	bool last_instr_present; // Has an instruction the parsing bits 0b11 set (is last instruction).
	bool is_valid; // Is it a valid packet? Do we know which instruction is the first?
	ut32 hw_loop0_addr; // Start address of hardware loop 0
	ut32 hw_loop1_addr; // Start address of hardware loop 1
	ut64 last_access; // Last time accessed in milliseconds
	ut32 pkt_addr; // Address of the packet. Equals the address of the first instruction.
	bool is_eob; // Is this packet the end of a code block? E.g. contains unconditional jmp.
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
} HexState;