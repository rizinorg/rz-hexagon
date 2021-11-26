# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

ALL_REG_NAMES = list()  # R0, ..., R30, R31, ..., C3, C1_0, ..., UPCYCLELO, VFR0, ...
LLVM_FAKE_REGS = list()
CALLEE_SAVED_REGS = list()
CC_REGS = dict()  # The register used in the calling convention. Argument and return regs.

INSTRUCTION_LENGTH = 32

IMMEDIATE_TYPES = dict()
REG_CLASS_NAMES = dict()

MAX_IMM_LEN = 32
duplex_constrains_info_shown = False
