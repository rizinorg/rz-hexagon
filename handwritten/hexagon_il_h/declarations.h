// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

/// Immutable bits of CTR registers as in QEMU.
static const ut64 hex_ctr_immut_masks[32] = {
    [HEX_REG_CTR_REGS_C8] = 0xc13000c0, // USR
    [HEX_REG_CTR_REGS_C9] = HEX_IMMUTABLE_REG, // PC
    [HEX_REG_CTR_REGS_C11] = 0x3f, // GP
    [HEX_REG_CTR_REGS_C14] = HEX_IMMUTABLE_REG, // UPCYCLELO
    [HEX_REG_CTR_REGS_C15] = HEX_IMMUTABLE_REG, // UPCYCLEHI
    [HEX_REG_CTR_REGS_C30] = HEX_IMMUTABLE_REG, // UTIMERLO
    [HEX_REG_CTR_REGS_C31] = HEX_IMMUTABLE_REG, // UTIMERHI
};

RZ_IPI bool hex_shuffle_insns(RZ_INOUT HexPkt *p);
RZ_IPI RzILOpEffect *hex_get_il_op(const ut32 addr, const bool get_pkt_op);
RZ_IPI RZ_OWN RzILOpPure *hex_get_rf_property_val(const HexRegFieldProperty property, const HexRegField field);
RZ_IPI RZ_OWN RzILOpEffect *hex_get_npc(const HexPkt *pkt);
RZ_IPI RZ_OWN RzILOpEffect *hex_il_op_jump_flag_init(HexInsnPktBundle *bundle);
RZ_IPI RZ_OWN RzILOpEffect *hex_il_op_next_pkt_jmp(HexInsnPktBundle *bundle);
RZ_IPI RZ_OWN RzILOpEffect *hex_commit_packet(HexInsnPktBundle *bundle);
RZ_IPI RZ_OWN RzILOpEffect *hex_write_reg(RZ_BORROW HexInsnPktBundle *bundle, const HexOp *op, RzILOpPure *val);
RZ_IPI RZ_OWN RzILOpPure *hex_read_reg(RZ_BORROW HexPkt *pkt, const HexOp *op, bool tmp_reg);
RZ_IPI RZ_OWN RzILOpEffect *hex_cancel_slot(RZ_BORROW HexPkt *pkt, ut8 slot);
RZ_IPI void hex_reset_il_pkt_stats(HexILExecData *stats);
RzILOpPure *hex_get_corresponding_cs(RZ_BORROW HexPkt *pkt, const HexOp *Mu);
