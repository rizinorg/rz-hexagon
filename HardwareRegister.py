# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import re

import HexagonArchInfo
import PluginInfo
from Register import Register
from helperFunctions import list_to_int
from ImplementationException import ImplementationException


class HardwareRegister(Register):
    """Represents a concrete Hexagon hardware register. Like R13, C17, V4 etc."""

    def __init__(self, llvm_reg_class: str, llvm_object: dict, name: str, size: int):
        index = list_to_int(llvm_object["HWEncoding"], endian="little")
        # We use the super class only to set all the register type flags.
        super().__init__(
            llvm_syntax=name,
            llvm_reg_class=llvm_reg_class,
            index=index,
            is_new_value=False,
        )
        self.name: str = name
        self.asm_name = ""
        self.alias = ""
        self.set_well_defined_asm_names(llvm_object["AsmName"], llvm_object["AltNames"])
        self.dwarf_numbers = llvm_object["DwarfNumbers"]
        self.enum_name = (
            PluginInfo.REGISTER_ENUM_PREFIX
            + HardwareRegister.register_class_name_to_upper(llvm_reg_class)
            + "_"
            + re.sub(r":", "_", self.asm_name).upper()
        )
        self.sorting_val = int(re.sub(r"[a-zA-Z:]", "", self.asm_name))  # Remove letter and ':' from name.

        self.hw_encoding = index
        self.size: int = size if not self.is_vector else size * 2
        self.sub_register_names: list = [
            r["def"] for r in llvm_object["SubRegs"] if r["def"] not in HexagonArchInfo.LLVM_FAKE_REGS
        ]

    def __lt__(self, other):
        return self.sorting_val < other.sorting_val

    def set_well_defined_asm_names(self, llvm_asm: str, llvm_alt: list):
        """LLVM is inconsistent about register naming styles.
        Sometimes the 's49' style is the alias, sometimes the 'pmucnt1' style is the alias.
        Here we define: Alias style = 'lr:fp' Asm style = 'r31:30' and set the attributes accordingly.
        """

        match_asm = re.search(r"^[rcpgvqs]\d{1,2}(:\d{1,2})?$", llvm_asm)
        match_alias = re.search(r"^[rcpgvqs]\d{1,2}(:\d{1,2})?$", ",".join(llvm_alt))
        if (llvm_asm == "p3:0") or (llvm_asm in llvm_alt):
            match_asm = None
        if match_asm and match_alias:
            raise ImplementationException(
                "HW reg alias and asm names match same pattern: alias: {} asm: {}".format(",".join(llvm_alt), llvm_asm)
            )
        elif match_asm:
            self.asm_name = llvm_asm
            self.alias = llvm_alt
        elif match_alias:
            self.asm_name = llvm_alt[0]
            self.alias = [llvm_asm]
        else:
            raise ImplementationException(
                "Alias and asm name of HW reg has no well defined name: alias: {} asm: {}".format(
                    ",".join(llvm_alt), llvm_asm
                )
            )

    # RIZIN SPECIFIC
    @staticmethod
    def get_parse_code_reg_bits(reg_class: str, var: str) -> str:
        """Sub register bits are encoded in a space saving way in the instruction encoding.
        So we need to shift the bits around before we get the register ID. Here we generate the code for that.
        """
        indent = PluginInfo.LINE_INDENT
        code = ""
        if reg_class == "CtrRegs64" or reg_class == "DoubleRegs" or reg_class == "GuestRegs64" or reg_class == "HvxVQR":
            # TODO Assumption: test with actual disassembly
            #  GuestRegs64  -> OK
            #  DoubleRegs   -> OK
            #  CtrRegs64    -> MIXED (Missing regs in llvm) C21:20 - C29:28. But they follow the parsing pattern.
            #  HvxVQR       -> FAILS Public HexagonSDK does not support those instructions yet.
            # code += "{v} = {v};\n".format(v=var)
            pass
        elif reg_class == "GeneralDoubleLow8Regs":
            code += "{v} = {v} << 1;\n".format(v=var)
            code += "if ({} > 6) {{  // HEX_REG_D3 == 6\n".format(var)
            code += "{}{} = ({} & 0x7) | 0x10;\n}}".format(indent, var, var)
            pass
        elif reg_class == "GeneralSubRegs":
            code += "if ({} > 7) {{  // HEX_REG_R7 == 7\n".format(var)
            code += "{}{} = ({} & 0x7) | 0x10;\n}}".format(indent, var, var)
            return code
        elif reg_class == "VectRegRev":
            # TODO Assumption: test with actual disassembly
            #  No instructions in LLVM found yet.
            #  Public HexagonSDK does not support those instructions yet.
            code += "{v} = ({v} << 1) + 1;\n".format(v=var)
        elif reg_class == "ModRegs":
            # ModRegs are effectively control registers. M0 = C6, M1 = C7
            code += "{} |= 6;\n".format(var)
        return code

    # RIZIN SPECIFIC
    def get_reg_profile(self, offset: int, is_tmp: bool) -> str:
        """Returns a one line register profile description.

        Parameters:
            offset: The offset into the memory where the register bits are stored.
            is_tmp: True if a tmp register profile line should be generated (tmp regs are for RZIL VM).
        returns: "type name size mem-offset packed-size"
        """
        indent = PluginInfo.LINE_INDENT
        aname = self.asm_name.upper()
        return '"{t}{i}{n}{i}.{s}{i}{o}{i}0\\n"'.format(
            t=self.get_rz_reg_type(),
            n=aname if not is_tmp else aname + "_tmp",
            s=self.size if not (self.llvm_reg_class == "PredRegs") else 8,
            o=str(offset),
            i=indent,
        )

    # RIZIN SPECIFIC
    def get_rz_reg_type(self) -> str:
        if self.is_control and self.is_hvx:
            return "vcc"
        elif self.is_vector:
            return "vc"
        elif self.is_control:
            return "ctr"
        elif self.is_general or self.is_guest:
            return "gpr"
        elif self.is_system:
            return "sys"
        else:
            raise ImplementationException("Rizin has no register type for the register {}".format(self.llvm_type))
