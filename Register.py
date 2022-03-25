# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import re

from ImplementationException import ImplementationException
from Operand import Operand


class Register(Operand):
    """The class which represents a Hexagon Register.

    Attributes:

    - llvm_syntax_name: :class:`str` Name of the register as it is found in the llvm src: Rd32, Pu4, Vd32...
    - llvm_reg_class: :class:`str` The register class this register belongs to (Double Register, General Register etc.)

    - is_general: :class:`bool` General registers: R0-R31
    - is_double: :class:`bool` True if pair of register: R0:1 etc. LLVM uses Dx syntax for them: R1:0 = D0, R3:2 = D2
    - is_control: :class:`bool` True if it is a control register. False otherwise.
    - is_hvx: :class:`bool` True if it is an HVX register. False otherwise.
    - is_guest :class:`bool` True if it is a register of the guest. False otherwise. Only accessible from Guest-Mode
    - sub_instr_encoding: :class:`bool` Registers usable by sub instructions.
    - is_lower8: :class:`bool` True if one of the lower 8 registers for sub instructions: R0-R7 and D11-D8 + D3-D0
    - is_mod: :class:`bool` True if it is a Mod control register.
    - is_is_predicate :class:`bool` True if it is a predicate register.
    - is_new_value: :class:`bool` True if it holds a new value within the instruction packet. In syntax: R8.new
    """

    __slots__ = [
        "is_double",
        "is_predicate",
        "is_control",
        "is_system",
        "is_new_value",
        "llvm_syntax",
        "syntax_index",
        "is_hvx",
        "is_general",
        "is_lower8",
        "sub_instr_encoding",
        "is_mod",
        "is_guest",
        "llvm_reg_class",
        "is_vector",
        "is_quadruple",
        "is_n_reg",
    ]

    def __init__(
        self,
        llvm_syntax: str,
        llvm_reg_class: str,
        is_new_value: bool,
        index: int,
    ):
        super(Register, self).__init__(llvm_syntax, llvm_reg_class, index)
        self.llvm_syntax = llvm_syntax
        self.llvm_reg_class = llvm_reg_class
        self.llvm_type = llvm_reg_class

        # Register types
        self.is_general = False
        self.is_double = False
        self.is_quadruple = False
        self.is_control = False
        self.is_hvx = False
        self.is_vector = False
        # Nt.new register is one of the destination register of the other instructions in the packet.
        self.is_n_reg = re.search(r"N.8", llvm_syntax) is not None
        # Register of the guest VM: GELR, GSR, GOSP, G3-15, GPMUCNT4-7, G20-23 etc.
        self.is_guest = False
        self.is_system = False

        # Registers usable by sub instructions. This implies a different encoding of the register number because of the
        # space constrains for sub instructions.
        # For example the use of only 4bits instead of 5:
        # 0b0000 = R0, 0b1000 = R16, 0b1111 = R23
        # Once the register number is >0b111 we have to shift the encoding once to the left to get the correct
        # register number.
        #
        # Same for DoubleRegs:
        # R5:4 = D2 - Bit encoding: 0b010
        # R17:16 = D8  - Bit encoding: 0b100
        self.sub_instr_encoding = False
        self.is_lower8 = False  # Register R0-R7 and D11-D8 + D3-D0

        # Control register sub-types
        self.is_mod = False  # Modifier register
        self.is_predicate = False

        self.is_new_value = is_new_value

        self.parse_reg_type()

    def parse_reg_type(self) -> None:
        """Sets flags according the register type."""
        if self.llvm_reg_class == "IntRegs":
            self.is_general = True
        elif self.llvm_reg_class == "IntRegsLow8":  # Register R0-R7
            self.is_general = True
            self.is_lower8 = True
        elif self.llvm_reg_class == "GeneralSubRegs":  # R0-R7, R16-R23
            self.is_general = True
            self.sub_instr_encoding = True
        elif self.llvm_reg_class == "DoubleRegs":  # D0 = R1_0,
            self.is_general = True
            self.is_double = True
        elif (
            self.llvm_reg_class == "GeneralDoubleLow8Regs"
        ):  # D0,D1,D2,D3,D8,D9,D10,D11
            self.is_general = True
            self.sub_instr_encoding = True
            self.is_double = True
            self.is_lower8 = True
        elif self.llvm_reg_class[:3] == "Hvx":
            self.is_hvx = True
            if self.llvm_reg_class == "HvxQR":
                self.is_control = True
                self.is_predicate = True
            elif self.llvm_reg_class == "HvxVR":
                self.is_vector = True
            elif self.llvm_reg_class == "HvxWR":  # Vector register
                self.is_vector = True
                self.is_double = True
            elif self.llvm_reg_class == "HvxVQR":
                self.is_vector = True
                self.is_quadruple = True
            else:
                raise ImplementationException(
                    "Unhandled HVX register type: {}".format(self.llvm_reg_class)
                )
        elif self.llvm_reg_class == "CtrRegs":
            self.is_control = True
        elif self.llvm_reg_class == "CtrRegs64":
            self.is_control = True
            self.is_double = True
        elif self.llvm_reg_class == "PredRegs":
            self.is_control = True
            self.is_predicate = True
        elif self.llvm_reg_class == "ModRegs":
            self.is_control = True
            self.is_mod = True
        elif self.llvm_reg_class == "GuestRegs":
            self.is_guest = True
        elif self.llvm_reg_class == "GuestRegs64":  # G1:0 = G1_0, G3:2 etc.
            self.is_guest = True
            self.is_double = True
        elif self.llvm_reg_class == "SysRegs":
            self.is_system = True
        elif self.llvm_reg_class == "SysRegs64":
            self.is_system = True
            self.is_double = True
        else:
            raise ImplementationException(
                "Unhandled register type: {}".format(self.llvm_reg_class)
            )

    # RIZIN SPECIFIC
    def add_code_for_opcode_parsing(self, parsing_code: str) -> None:
        """Overrides method of parent class. Here we add code which does specific parsing of the operand value on
        disassembly.
        """
        self.code_opcode_parsing = parsing_code + "; // {}\n".format(self.llvm_syntax)
