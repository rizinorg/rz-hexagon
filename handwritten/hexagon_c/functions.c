// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
//
// SPDX-License-Identifier: LGPL-3.0-only

inline bool hex_if_duplex(uint32_t insn_word) {
	if (((insn_word & 0xc000) >> 18) == 0) {
		return true;
	}
	return false;
}

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

void hex_set_pkt_info(HexPktInfo* i_pkt_info) {
    static HexPkt pkt = {0};  // Current packet
    static ut8 i = 0;  // Index of the instruction in the current packet.
    static ut8 p0 = 255;
    static ut8 p1 = 255;
    static bool new_pkt_starts = true;

    memcpy(&pkt.i_infos[i], i_pkt_info, sizeof(HexPktInfo));

    // Parse instr. position in pkt
    if (new_pkt_starts && is_last_instr(i_pkt_info->parse_bits)) {  // Single instruction packet.
        // TODO No indent in visual mode for "[" without spaces.
        //  Possible cause: 2 extra bytes in UTF-8 chars are printed as spaces?
        strncpy(i_pkt_info->syntax_prefix, "[    ", 8);
        i_pkt_info->first_insn = true;
        i_pkt_info->last_insn = true;
        new_pkt_starts = true;
        i = 0;
    }
    else if (new_pkt_starts) {
        strncpy(i_pkt_info->syntax_prefix, "/", 8);  // TODO Add utf8 option "┌"
        i_pkt_info->first_insn = true;
        new_pkt_starts = false;
        // Just in case evil persons set the parsing bits incorrectly and pkts with more than 4 instr. occur.
        i = (i + 1) % 4;
    }
    else if (is_last_instr(i_pkt_info->parse_bits)) {
        strncpy(i_pkt_info->syntax_prefix, "\\", 8);  // TODO Add utf8 option "└"
        i_pkt_info->last_insn = true;
        new_pkt_starts = true;

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
    }
    else {
        strncpy(i_pkt_info->syntax_prefix, "|", 8);  // TODO Add utf8 option "│"
        new_pkt_starts = false;
        i = (i + 1) % 4;
    }


}

static inline bool imm_is_extendable(ut32 const_ext, ut8 type) {
    return ((const_ext != 0) && (type == HEX_OP_TYPE_IMM));
}

static inline bool imm_is_scaled(HexOpAttr attr) {
    return (attr & HEX_OP_IMM_SCALED);
}

void hex_op_extend(RZ_INOUT HexOp *op, bool set_new_extender)
{
    // Constant extender value
    static ut32 constant_extender = 0;

    if (set_new_extender) {
        constant_extender = op->op.imm;
        return;
    }

	if (imm_is_extendable(constant_extender, op->type)) {
	    if (imm_is_scaled(op->attr)) {
	        op->op.imm = (op->op.imm >> op->shift);  // Extended immediate values won't get scaled. Redo it.
	    }
		op->op.imm = ((op->op.imm) & 0x3F) | (constant_extender);
	}
	constant_extender = 0;
}
