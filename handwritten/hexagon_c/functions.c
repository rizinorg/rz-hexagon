// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
//
// SPDX-License-Identifier: LGPL-3.0-only

static inline bool is_last_instr(const ut8 parse_bits) {
    // Duplex instr. (parse bits = 0) are always the last.
    return ((parse_bits == 0x3) || (parse_bits == 0x0));
}

static inline bool is_endloop0_pkt(const ut8 pi_0, const ut8 pi_1) {
    return ((pi_0 == 0x2) && ((pi_1 == 0x1) || (pi_1 == 0x3)));
}

static inline bool is_endloop1_pkt(const ut8 pi_0, const ut8 pi_1) {
    return ((pi_0 == 0x1) && (pi_1 == 0x2));
}

static inline bool is_endloop01_pkt(const ut8 pi_0, const ut8 pi_1) {
    return ((pi_0 == 0x2) && (pi_1 == 0x2));
}

void hex_set_pkt_info(RZ_INOUT HexPktInfo* i_pkt_info, const ut32 addr) {
    static HexPkt pkt = {0};  // Current packet
    static ut8 i = 0;  // Index of the instruction in the current packet.
    static ut8 p0 = 255;
    static ut8 p1 = 255;
    static ut32 previous_addr = 0;
    // Valid packet: A packet from which we know its *actual* first and last instruction.
    // Does this instruction belong to a valid packet?
    static bool valid_packet = true;
    static bool new_pkt_starts = true;

    // Only change valid_packet flag if the same instruction is not disassembled twice (e.g. for analysis and asm).
    if (previous_addr != addr) {
        // We can only know for sure, if the current packet is a valid packet,
        // if we have seen the instr. before the current one.
        // (addr == (previous_addr - 4) || addr == 0)
        //
        // In case the previous instruction belongs to a valid packet, we are still in a valid packet.
        // If it was part of an *invalid* packet, a new *valid* packet only begins, if the previous instruction
        // was the last of the invalid packet.
        valid_packet = (previous_addr == (addr - 4) || addr == 0) && (valid_packet || new_pkt_starts);
    }
    if (valid_packet) {
        memcpy(&pkt.i_infos[i], i_pkt_info, sizeof(HexPktInfo));
    }
    // Parse instr. position in pkt
    if (new_pkt_starts && is_last_instr(i_pkt_info->parse_bits)) {  // Single instruction packet.
        new_pkt_starts = true;
        // TODO No indent in visual mode for "[" without spaces.
        if (valid_packet) {
            strncpy(i_pkt_info->syntax_prefix, "[    ", 8);
            i_pkt_info->first_insn = true;
            i_pkt_info->last_insn = true;
            i = 0;
        } else {
            strncpy(i_pkt_info->syntax_prefix, "?", 8);
        }
    }
    else if (new_pkt_starts) {
        new_pkt_starts = false;
        if (valid_packet) {
            strncpy(i_pkt_info->syntax_prefix, "/", 8);  // TODO Add utf8 option "┌"
            i_pkt_info->first_insn = true;
            i_pkt_info->last_insn = false;
            // Just in case evil persons set the parsing bits incorrectly and pkts with more than 4 instr. occur.
            i = (i + 1) % 4;
        } else {
            strncpy(i_pkt_info->syntax_prefix, "?", 8);
        }
    }
    else if (is_last_instr(i_pkt_info->parse_bits)) {
        new_pkt_starts = true;
        if (valid_packet) {
            strncpy(i_pkt_info->syntax_prefix, "\\", 8);  // TODO Add utf8 option "└"

            i_pkt_info->first_insn = false;
            i_pkt_info->last_insn = true;

            p0 = pkt.i_infos[0].parse_bits;
            p1 = pkt.i_infos[1].parse_bits;
            if (is_endloop01_pkt(p0, p1)) {
                strncpy(i_pkt_info->syntax_postfix, " < endloop01", 16);  // TODO Add utf8 option "∎"
                i_pkt_info->loop_attr |= (HEX_ENDS_LOOP_0 | HEX_ENDS_LOOP_1);
            }
            else if (is_endloop0_pkt(p0, p1)) {
                strncpy(i_pkt_info->syntax_postfix, " < endloop0", 16);
                i_pkt_info->loop_attr |= HEX_ENDS_LOOP_0;
            }
            else if (is_endloop1_pkt(p0, p1)) {
                strncpy(i_pkt_info->syntax_postfix, " < endloop1", 16);
                i_pkt_info->loop_attr |= HEX_ENDS_LOOP_1;
            }
            i = 0;
        } else {
            strncpy(i_pkt_info->syntax_prefix, "?", 8);
        }
    }
    else {
        new_pkt_starts = false;
        if (valid_packet) {
            strncpy(i_pkt_info->syntax_prefix, "|", 8);  // TODO Add utf8 option "│"
            i = (i + 1) % 4;
        } else {
            strncpy(i_pkt_info->syntax_prefix, "?", 8);
        }
    }
    previous_addr = addr;
}

static inline bool imm_is_scaled(const HexOpAttr attr) {
    return (attr & HEX_OP_IMM_SCALED);
}

/**
 * @brief Applies the last constant extender to the immediate value of the given HexOp.
 *
 * @param op The operand the extender is applied to.
 * @param set_new_extender True if the immediate value of the op comes from immext() and sets the a new constant extender. False otherwise.
 * @param addr The address of the currently diassembled instruction.
 */
void hex_op_extend(RZ_INOUT HexOp *op, const bool set_new_extender, const ut32 addr)
{
	// Constant extender value
	static ut64 constant_extender = 0;
	static ut32 prev_addr = 0;

	if (op->type != HEX_OP_TYPE_IMM) {
		goto set_prev_addr_return;
	}

	if (set_new_extender) {
		constant_extender = op->op.imm;
		goto set_prev_addr_return;
	}

	if ((addr - 4) != prev_addr) {
		// Disassembler jumped to somewhere else in memory than the next address.
        if (!set_new_extender) {
		    constant_extender = 0;
        }
		goto set_prev_addr_return;
	}

    if (constant_extender != 0) {
        op->op.imm = imm_is_scaled(op->attr) ? (op->op.imm >> op->shift) : op->op.imm;
        op->op.imm = ((op->op.imm & 0x3F) | constant_extender);
        constant_extender = 0;
    }
    
	set_prev_addr_return:
		prev_addr = addr;
		return;
}

