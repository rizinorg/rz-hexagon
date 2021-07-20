# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import re

import HexagonArchInfo
import PluginInfo
from ImplementationException import ImplementationException
from Register import Register
from helperFunctions import list_to_int


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
        self.enum_name = (
            PluginInfo.REGISTER_ENUM_PREFIX
            + HardwareRegister.register_class_name_to_upper(llvm_reg_class)
            + "_"
            + self.name
        )
        self.alias = llvm_object["AltNames"]
        self.asm_name = llvm_object["AsmName"]
        self.hw_encoding = index
        self.size: int = size if not self.is_vector else size * 2
        self.sub_register_names: list = [
            r["def"]
            for r in llvm_object["SubRegs"]
            if r["def"] not in HexagonArchInfo.LLVM_FAKE_REGS
        ]

    # RIZIN SPECIFIC
    @staticmethod
    def get_func_name_of_class(reg_class: str) -> str:
        """Generates the function name for register name retrieval in the disassembler code."""
        reg_func = HardwareRegister.register_class_name_to_upper(reg_class).lower()
        code = PluginInfo.GENERAL_ENUM_PREFIX.lower() + "get_" + reg_func
        return code

    # RIZIN SPECIFIC
    @staticmethod
    def get_parse_code_reg_bits(reg_class: str, var: str) -> str:
        """Sub register bits are encoded in a space saving way in the instruction encoding.
        So we need to shift the bits around before we get the register ID. Here we generate the code for that.
        """
        indent = PluginInfo.LINE_INDENT
        code = ""
        if (
            reg_class == "CtrRegs64"
            or reg_class == "DoubleRegs"
            or reg_class == "GuestRegs64"
            or reg_class == "HvxVQR"
        ):
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
    def get_reg_profile(self, offset: int) -> str:
        """Returns a one line register profile description.

        Parameters:
            offset: The offset into the memory where the register bits are stored.
        returns: "type name size mem-offset packed-size"
        """
        indent = PluginInfo.LINE_INDENT
        return '"{t}{i}{n}{i}.{s}{i}{o}{i}0\\n"'.format(
            t=self.get_rz_reg_type(),
            n=self.asm_name.lower(),
            s=self.size,
            o=str(offset),
            i=indent,
        )

    # RIZIN SPECIFIC
    def get_rz_reg_type(self) -> str:
        return "gpr"
        # if self.is_vector:
        #     return "vcr"
        # elif self.is_control:
        #     return "ctr"
        # elif self.is_general:
        #     return "gpr"
        # elif self.is_guest:
        #     return "gst"
        # else:
        #     raise ImplementationException("Rizin has no register type for the register {}".format(self.llvm_type))

    @staticmethod
    def register_class_name_to_upper(s: str) -> str:
        """Separates words by an '_' and sets them upper case: IntRegsLow8 -> INT_REGS_LOW8"""
        matches = re.findall(r"[A-Z][a-z0-9]+", s)
        for match in matches:
            s = re.sub(match, match.upper() + "_", s)
        if s[-1] == "_":
            s = s[:-1]
        return s
