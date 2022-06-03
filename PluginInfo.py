# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

HEX_INSTR_VAR_SYNTAX = "hi_u32"
LINE_INDENT = "\t"
REPO_URL = "https://github.com/rizinorg/rz-hexagon"
GENERATION_WARNING_DELIMITER = "//" + "=" * 40
GENERAL_ENUM_PREFIX = "HEX_"
GENERAL_FCN_PREFIX = "hex_"
INSTR_ENUM_PREFIX = GENERAL_ENUM_PREFIX + "INS_"
REGISTER_ENUM_PREFIX = GENERAL_ENUM_PREFIX + "REG_"
REGISTER_ALIAS_ENUM_PREFIX = REGISTER_ENUM_PREFIX + "ALIAS_"
REGISTER_LOOKUP_TABLE_NAME_V69 = "hexagon_{}_lt_v69"
ALIAS_REGISTER_LOOKUP_TABLE_v69 = "hex_alias_reg_lt_v69"

FRAMEWORK_NAME = "rizin"
MAX_OPERANDS = 6
NUM_HEX_IL_INSN_MEMBERS = 3
