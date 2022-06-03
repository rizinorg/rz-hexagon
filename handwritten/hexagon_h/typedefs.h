// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

typedef struct {
	const char *name;
	const char *alias;
	const char *name_tmp;
	const char *alias_tmp;
} HexRegNames;

typedef struct {
	ut32 /* Reg class */ cls;
	ut32 /* Reg Enum */ reg_enum;
} HexRegAliasMapping;

typedef enum {
	HEX_OP_TYPE_IMM,
	HEX_OP_TYPE_REG,
} HexOpType;

/**
 * \brief Flags to mark which kind of predicates instructions use.
 */
typedef enum {
	HEX_NOPRED, ///< no conditional execution
	HEX_PRED_TRUE, ///< if (Pd) ...
	HEX_PRED_FALSE, ///< if (!Pd) ...
	HEX_PRED_NEW, ///< if (Pd.new) or if (!Pd.new)
} HexPred;

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
	char text_prefix[16]; // Package indicator
	char text_postfix[24]; // for ":endloop" string.
} HexPktInfo;

typedef struct {
	ut8 /* HexOpType */ type; ///< Operand type: Immediate or register
	ut8 class; ///< Equivalent to: HexRegClass (for registers) OR HexOpTemplateFlag (for immediate values).
	char isa_id; ///< The identifier character in the ISA of this instruction: 'd' for Rdd, I for Ii etc. 0x0 if not known.
	union {
		ut8 reg; ///< Register number. E.g. 3 for R3 etc.
		st64 imm; ///< Immediate value.
	} op; ///< Actual value of the operand.
	HexOpAttr attr; ///< Attributes of the operand.
	ut8 shift; ///< Number of bits to shift the bits in the opcode to retrieve the operand value.
} HexOp;

typedef RzILOpEffect *(*HexILOpGetter)(void /* HexInsnPktBundle */ *);

typedef enum {
	HEX_IL_INSN_ATTR_INVALID = 0, ///< Operation was not set or implemented.
	HEX_IL_INSN_ATTR_NONE = 1 << 0, ///< Nothing special about this operation.
	HEX_IL_INSN_ATTR_COND = 1 << 1, ///< Executes differently if a certain condition is met.
	HEX_IL_INSN_ATTR_SUB = 1 << 2, ///< Operation is a sub-instruction.
	HEX_IL_INSN_ATTR_BRANCH = 1 << 3, ///< Operation contains a branch.
	HEX_IL_INSN_ATTR_MEM_READ = 1 << 4, ///< Operation reads from the memory.
	HEX_IL_INSN_ATTR_MEM_WRITE = 1 << 5, ///< Operation writes to the memory.
	HEX_IL_INSN_ATTR_NEW = 1 << 6, ///< Operation reads a .new value.
	HEX_IL_INSN_ATTR_WPRED = 1 << 7, ///< Operation writes a predicate register.
	HEX_IL_INSN_ATTR_WRITE_P0 = 1 << 8, ///< Writes predicate register P0
	HEX_IL_INSN_ATTR_WRITE_P1 = 1 << 9, ///< Writes predicate register P1
	HEX_IL_INSN_ATTR_WRITE_P2 = 1 << 10, ///< Writes predicate register P2
	HEX_IL_INSN_ATTR_WRITE_P3 = 1 << 11, ///< Writes predicate register P3
} HexILInsnAttr;

/**
 * \brief Represents a single operation of an instruction.
 */
typedef struct {
	HexILOpGetter get_il_op; ///< Pointer to the getter to retrieve the RzILOpEffects of this operation.
	HexILInsnAttr attr; ///< Attributes to shuffle it to the correct position in the packets IL ops.
	void /* HexInsn */ *hi; ///< The instruction this op belongs to.
} HexILOp;

/**
 * \brief Struct of instruction operations. Usually an instruction has only one operation
 * but duplex and compound instructions can have more.
 * The last op in this struct has all members set to NULL/0.
 */
typedef struct {
	HexILOp op0;
	HexILOp op1;
	HexILOp end;
} HexILInsn;

typedef struct {
	bool is_sub; ///< Flag for sub-instructions.
	ut8 op_count; ///< The number of operands this instruction has.
	ut32 addr; ///< Memory address the instruction is located (high sub-instruction is unaligned by 2 byte!).
	ut32 opcode; ///< The instruction opcode.
	HexPred pred; ///< The instruction predicate.
	HexInsnID identifier; ///< The instruction identifier
	char text_infix[128]; ///< Textual disassembly of the instruction.
	HexOp ops[HEX_MAX_OPERANDS]; ///< The operands of the instructions.
	HexILInsn il_insn; ///< RZIL instruction. These are not meant for execution! Use the packet ops for that.
	ut8 slot; ///< The slot the instruction occupies.
	RzFloatRMode fround_mode; ///< The float rounding mode of the instruction.
} HexInsn;

/**
 * \brief The instruction container holds one instruction or two sub-instructions if it is a duplex.
 * It stores meta information about those instruction(s) like opcode, packet information or the parse bits.
 */
typedef struct {
	ut8 parse_bits; ///< Parse bits of instruction.
	bool is_duplex; ///< Does this container hold two sub-instructions?
	ut32 identifier; ///< Equals instruction ID if is_duplex = false. Otherwise: (high.id << 16) | (low.id & 0xffff)
	union {
		HexInsn *sub[2]; ///< Pointer to sub-instructions if is_duplex = true. sub[0] = high, sub[1] = low
		HexInsn *insn; ///< Pointer to instruction if is_duplex = false.
	} bin;
	ut32 addr; ///< Address of container. Equals address of instruction or of the high sub-instruction if this is a duplex.
	ut32 bytes; ///< The instruction bytes.
	HexPktInfo pkt_info; ///< Packet related information. First/last instr., prefix and postfix for text etc.
	// Deprecated members will be removed on RzArch introduction.
	RZ_DEPRECATE RzAsmOp asm_op; ///< Private copy of AsmOp. Currently only of interest because it holds the utf8 flag.
	RZ_DEPRECATE RzAnalysisOp ana_op; ///< Private copy of AnalysisOp. Analysis info is written into it.
	char text[296]; ///< Textual disassembly
} HexInsnContainer;

#define HEX_LOG_SLOT_BIT_OFF   4
#define HEX_LOG_SLOT_LOG_WIDTH 2
#define HEX_LOG_SLOT_LOG_MASK  0b11

/**
 * \brief Holds information about the execution of the packet.
 */
typedef struct {
	RzBitVector *slot_cancelled; ///< Flags for cancelled slots. If bit at (1 << slot i) is set, slot i is cancelled.
	RzBitVector *pred_read; ///< Predicate register (P0-P3) read, if flags set at (1 << reg_num) are set.
	RzBitVector *pred_tmp_read; ///< Tmp predicate register (P0-P3) read, if flags set at (1 << reg_num) are set.
	RzBitVector *pred_written; ///< Predicate register (P0-P3) written, if flags (3:0) are set at (1 << pred_num).
				   ///< The bits[11:4] are used to indicate the last slot which wrote to the predicate (2bit each).
				   ///< Details are necessary because, if instructions in different slots
				   ///< write to the same predicate, the result is ANDed.
	RzBitVector *gpr_read; ///< GPR register (R0-R31) read, if flags set at (1 << reg_num) are set.
	RzBitVector *gpr_tmp_read; ///< Tmp GPR register (R0-R31) read, if flags set at (1 << reg_num) are set.
	RzBitVector *gpr_written; ///< GPR register (R0-R31) written, if flags set at (1 << reg_num) are set.
	RzBitVector *ctr_read; ///< Control register (C0-C31) read, if flags set at (1 << reg_num) are set.
	RzBitVector *ctr_tmp_read; ///< Tmp control register (C0-C31) read, if flags set at (1 << reg_num) are set.
	RzBitVector *ctr_written; ///< Control register (C0-C31) written, if flags set at (1 << reg_num) are set.
} HexILExecData;

/**
 * \brief Represents an Hexagon instruction packet.
 * We do not assign instructions to slots, but the order of instructions matters nonetheless.
 * The layout of a real packet is:
 *
 * low addr | Slot 3
 * ---------+----------
 *          | Slot 2
 * ---------+----------
 *          | Slot 1    -> High Sub-Instruction of Duplex is always in Slot 1
 * ---------+----------
 * high addr| Slot 0    -> Low Sub-Instruction of Duplex is always in Slot 0
 *
 * Because of this order the textual disassembly of duplex instructions is: "<high-text> ; <low-text>".
 * Also, the high sub-instruction is located at the _lower_ memory address (aligned to 4 bytes).
 * The low sub-instruction at <high.addr + 2>.
 *
 * This said: The HexPkt.bin holds only instruction container, no instructions!
 * The container holds a normal instruction or two sub-instructions.
 */
typedef struct {
	bool last_instr_present; ///< Has an instruction the parsing bits 0b11 set (is last instruction).
	bool is_valid; ///< Is it a valid packet? Do we know which instruction is the first?
	bool is_eob; ///< Is this packet the end of a code block? E.g. contains unconditional jmp.
	HexLoopAttr hw_loop; ///< If the packet is the end of a hardware loop, it stores here from which one.s
	ut32 hw_loop0_addr; ///< Start address of hardware loop 0
	ut32 hw_loop1_addr; ///< Start address of hardware loop 1
	ut32 pkt_addr; ///< Address of the packet. Equals the address of the first instruction.
	ut64 last_access; ///< Last time accessed in milliseconds
	RzList /*<HexInsnContainer *>*/ *bin; ///< Descending by address sorted list of instruction containers.
	RzPVector /*<HexILOp *>*/ *il_ops; ///< Pointer to RZIL ops of the packet. If empty the il ops were not shuffled into order yet.
	HexILExecData il_op_stats; ///< Meta information about the IL operations executed (register read/written etc.)
} HexPkt;

/**
 * \brief This struct is given to the IL getter of each instruction.
 * They use it for resolving register names, alias and the like.
 */
typedef struct {
	const HexInsn *insn;
	HexPkt *pkt;
} HexInsnPktBundle;

typedef struct {
	ut32 addr; ///< Address of the instruction which gets the extender applied.
	ut32 const_ext; ///< The constant extender value.
} HexConstExt;

/**
 * \brief Flags for the debug printing about the state packet buffer.
 */
typedef enum {
	HEX_BUF_ADD = 0, ///< Instruction is added to a specific packet i.
	HEX_BUF_STALE = 1, ///< Instruction is written to a stale packet (overwrites old one).
	HEX_BUF_NEW = 2, ///< Instruction is written to a new packet (overwrites old one).
} HexBufferAction;

/**
 * \brief Buffer packets for reversed instructions.
 */
typedef struct {
	bool just_init; ///< Flag indicates if IL VM was just initialized.
	HexPkt pkts[HEXAGON_STATE_PKTS]; // buffered instructions
	RzList /*<HexConstExt *>*/ *const_ext_l; // Constant extender values.
	RzAsm rz_asm; // Copy of RzAsm struct. Holds certain flags of interesed for disassembly formatting.
	RzConfig *cfg;
	RzPVector /*<RzAsmTokenPattern *>*/ *token_patterns; ///< PVector with token patterns. Priority ordered.
} HexState;

/**
 * \brief Register fields of different registers.
 */
typedef enum {
	HEX_REG_FIELD_USR_LPCFG, ///< The LPCFG field of the USR register
	HEX_REG_FIELD_USR_OVF, ///< The OVF field of the USR register
} HexRegField;

typedef enum {
	HEX_RF_WIDTH,
	HEX_RF_OFFSET,
} HexRegFieldProperty;
