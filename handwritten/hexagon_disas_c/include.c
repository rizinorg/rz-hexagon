// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdbool.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_util/rz_hex.h>
#include <rz_analysis.h>
#include "hexagon.h"
#include "hexagon_insn.h"
#include "hexagon_arch.h"

#if ASAN && !defined(__clang__)
#define NO_OPT_IF_ASAN __attribute__((optimize(0)))
#else
#define NO_OPT_IF_ASAN
#endif
