// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

HexState hexagon_state = { 0 };

static inline bool is_last_instr(const ut8 parse_bits) {
    // Duplex instr. (parse bits = 0) are always the last.
    return ((parse_bits == 0x3) || (parse_bits == 0x0));
}

static HexInsn *instr_in_pkt(const HexPkt *instr, const HexPkt *p) {
    if (!instr && !p) {
        return NULL;
    }
    HexInsn *i;
    rz_list_foreach_iter(p->insn, i) {
        if (instr->addr == i->addr) {
            return i;
        }
    }

    return NULL;
}

static HexInsn *instr_in_state(const HexPkt *instr) {
    if (!instr) {
        return NULL;
    }

    for (int i=0; i<HEXAGON_STATE_PKTS; ++i) {
        HexPkt p = hexagon_state.pkts[i];
        HexInsn *i;
        rz_list_foreach_iter(p.insn, i) {
            if (instr->addr == i->addr) {
                return i;
            }
        }
    }
    return NULL;
}

void hex_insn_free(HexInsn *i) {
    if (i) {
        free(i);
    }
}

void hex_init_state() {
    static bool init_done = false;
    if (!init_done) {
        for (int i=0; i<HEXAGON_STATE_PKTS; ++i) {
            memset(&(hexagon_state.pkts[i]), 0, sizeof(HexPkt));

            hexagon_state.pkts[i].ins = rz_list_newf(hex_insn_free);
            if (!hexagon_state.pkts.ins) {
                RZ_LOG_FATAL("Could not initilize instruction list!");
            }
            hex_clear_pkt(&(hexagon_state.pkts[i]));
        }
        init_done = true;
    }
}

/**
 * @brief Adds an instruction to a packet it belongs to.
 * If the instruction does not fit to any packet, it will be written to a new one.
 * 
 * @param new_ins The instruction to be copied.
 * @return The pointer to the added instruction. Null if the instruction could not be added.
 */
HexInsn *hex_add_instr_to_state(const HexInsn *new_ins) {
    // Search for preceding or next instruction in packets.
    bool add_to_pkt = false;
    bool overwrite_pkt = false;
    bool write_to_stale_pkt = false;
    // Insert new instruction before the neighbor instruction = True. Insert after = false
    bool insert_before = false;
    ut8 k = 0; // Instruction position in packet.

    HexInsn *hi = instr_in_state(new_ins);
    if (hi) {
        // Instruction already present.
        return hi;
    }
    HexPkt *p;

    for (ut8 i=0; i<HEXAGON_STATE_PKTS; ++i) {
        p = &(hexagon_state.pkts[i]);
        HexInsn pkt_ins; // Instructions already in the packet.
        rz_list_foreach_iter(p->insn, pkt_instr) {
            if (new_ins->addr == 0x0) {
                write_to_stale_pkt = true;
                break;
            }
            else if ((new_ins->addr == pkt_instr->addr - 4) && !(rz_list_length(p->insn) >= 3)) {
                // Instruction preceeds one in the packet.
                if (is_last_instr(new_ins->parse_bits)) {
                    // New instruction preceeds one, but does not belong to the packet.
                    // It belongs to the preceeding packet.
                    write_to_stale_pkt = true;
                    break;
                } else {
                    // The new instruction preceeds an instruction which is already in the packet.
                    insert_before = true;
                    add_to_pkt = true;
                    break;
                }
            }
            else if (new_ins->addr == pkt_instr->addr + 4) {
                if (!is_last_instr(pkt_instr->parse_bits) && !(rz_list_length(p->insn) >= 3)) {
                    // The previous instruction in this packet is not the last one.
                    // Add the new one to the packet.
                    add_to_pkt = true;
                    break;
                } else if (is_last_instr(pkt_instr->parse_bits)) {
                    overwrite_pkt = true;
                    break;
                }
            }
            ++k;
        }
        if (add_to_pkt || overwrite_pkt || write_to_stale_pkt) { // Break out of for(i) loop.
            break;
        }
    }

    // Add the instruction to packet p
    if (add_to_pkt) {
        HexInsn *ins = malloc(sizeof(HexInsn));
        memcpy(ins, new_ins, sizeof(HexInsn));
        if (insert_before) {
            rz_list_insert(p->insn, k, ins);
        } else {
            rz_list_insert(p->insn, k+1, ins);
            p->last_instr_present |= is_last_instr(ins->parse_bits);
        }
    } else if (overwrite_pkt) {
        bool loop_attr = p->loop_attr;
        bool valid = (p->is_valid || p->last_instr_present);
        hex_clear_pkt(p);
        p->loop_attr = loop_attr;
        p->valid = valid;
        p->last_instr_present |= is_last_instr(ins->parse_bits);
        rz_list_insert(p->insn, 0, ins);
    } else {
        p = hex_get_stale_state_pkt()
        hex_clear_pkt(p);
        p->last_instr_present |= is_last_instr(ins->parse_bits);
        rz_list_insert(p->insn, 0, ins);
    }
    p->last_access = rz_time_now();
}

/**
 * @brief Get the instruction at a given address.
 * 
 * @param addr The address of the instruction.
 * @return Pointer to instruction or NULL if none has been found.
 */
HexInsn *hex_get_instr_at_addr(const ut32 addr) {
    HexPkt *p;
    for (ut8 i=0; i<HEXAGON_STATE_PKTS; ++i) {
        p = &hexagon_state.pkts[i];
        HexPkt *i;
        rz_list_foreach_iter(p->insn, i) {
            if (addr == i->addr) {
                return i;
            }
        }
    }
    return NULL;
}

/**
 * @brief Clears a packet and sets its address to invalid values.
 * 
 * @param p The packet to clear.
 */
void hex_clear_pkt(HexPkt *p) {
    p->loop_attr = HEX_NO_LOOP;
    p->last_instr_present = false;
    p->is_valid = false;
    p->constant_extenders[0] = p->constant_extenders[1] = UT32_MAX;
    p->last_access = 0;
    HexPkt *i;
    rz_list_foreach_iter(p->insn, i) {
        rz_list_delete(p->insn, i);
    }
}

/**
 * @brief Gives the least accessed state packet.
 * 
 * @return HexPkt* Pointer to the oldest packet.
 */
HexPkt *hex_get_stale_state_pkt() {
    HexPkt *stale_state_pkt = &hexagon_state.pkts[0];
    ut64 oldest = UT64_MAX;

    for (ut8 i=0; i<HEXAGON_STATE_PKTS; ++i) {
        if (hexagon_state.pkts[i].last_access < oldest) {
            stale_state_pkt = &hexagon_state.pkts[i];
        }
    }
    return stale_state_pkt;
}