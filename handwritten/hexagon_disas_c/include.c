// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdbool.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include "hexagon.h"
#include "hexagon_insn.h"

extern HexPkt current_pkt;

static inline bool update_current_pkt(const ut32 addr, const ut32 prev_addr, const HexInsn *hi) {
    return (addr == 0x0 || ((addr - 4) == prev_addr) || hi->pkt_info.first_insn);
}

