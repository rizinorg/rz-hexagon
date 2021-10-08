// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define HEXAGON_STATE_PKTS 8

/**
 * @brief Buffer packets for reversed instructions.
 * 
 */
typedef struct {
    HexPkt pkts[HEXAGON_STATE_PKTS];
} HexState;
