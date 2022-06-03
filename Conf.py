# SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: LGPL-3.0-only

import subprocess

from enum import StrEnum
from pathlib import Path

from helperFunctions import log


class OutputFile(StrEnum):
    """
    Enum of paths used by the components.

    <REPO> is replaced with the path to the repositories root.
    <ARCH> is replaced with the architecture name.
    """

    OUT_BASE = "<REPO>/rizin/"
    LIBRZ_DIR = "<REPO>/rizin/librz/"
    IL_OPS_DIR = "<REPO>/rizin/librz/analysis/arch/hexagon/il_ops/"

    ANA_TESTS = "<REPO>/rizin/test/db/analysis/hexagon"
    ASM_TESTS = "<REPO>/rizin/test/db/asm/hexagon"
    RZIL_TESTS = "<REPO>/rizin/test/db/rzil/hexagon"
    ANALYSIS_HEXAGON_C = "<REPO>/rizin/librz/analysis/p/analysis_hexagon.c"
    ASM_HEXAGON_C = "<REPO>/rizin/librz/asm/p/asm_hexagon.c"
    CC_HEXAGON_32_SDB_TXT = "<REPO>/rizin/librz/analysis/d/cc-hexagon-32.sdb.txt"
    HEXAGON_IL_C = "<REPO>/rizin/librz/analysis/arch/hexagon/hexagon_il.c"
    HEXAGON_IL_GETTER_TABLE_H = "<REPO>/rizin/librz/analysis/arch/hexagon/hexagon_il_getter_table.h"
    HEXAGON_IL_H = "<REPO>/rizin/librz/analysis/arch/hexagon/hexagon_il.h"
    HEXAGON_ARCH_C = "<REPO>/rizin/librz/asm/arch/hexagon/hexagon_arch.c"
    HEXAGON_ARCH_H = "<REPO>/rizin/librz/asm/arch/hexagon/hexagon_arch.h"
    HEXAGON_C = "<REPO>/rizin/librz/asm/arch/hexagon/hexagon.c"
    HEXAGON_DISAS_C = "<REPO>/rizin/librz/asm/arch/hexagon/hexagon_disas.c"
    HEXAGON_H = "<REPO>/rizin/librz/asm/arch/hexagon/hexagon.h"
    HEXAGON_INSN_H = "<REPO>/rizin/librz/asm/arch/hexagon/hexagon_insn.h"
    HEXAGON_REG_TABLES_H = "<REPO>/rizin/librz/asm/arch/hexagon/hexagon_reg_tables.h"
    HEXAGON_DWARF_REG_TABLE_H = "<REPO>/rizin/librz/analysis/hexagon_dwarf_reg_num_table.inc"


class Conf:
    """
    Holds all the configurable values like paths.
    """

    @staticmethod
    def replace_placeholders(path_str: str) -> str:
        if "<REPO>" in path_str:
            root = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                check=True,
                stdout=subprocess.PIPE,
            )
            root_dir = Path(root.stdout.decode("utf8").strip("\n"))
            if not root_dir.exists():
                raise NotADirectoryError(str(root_dir))

            path_str = path_str.replace("<REPO>", str(root_dir))
        return path_str

    @staticmethod
    def get_path(file: OutputFile) -> Path:
        return Path(Conf.replace_placeholders(file))

    @staticmethod
    def check_path(path: Path, is_file: bool = True) -> None:
        """Checks a given path and creates the directory if it doesn't exist."""
        if not path.exists():
            target = path
            if is_file:
                target = path.parent
            log(f"Create dir {str(target)}")
            target.mkdir(parents=True, exist_ok=True)
