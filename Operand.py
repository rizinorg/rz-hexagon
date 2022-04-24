# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

from __future__ import annotations

from enum import Enum

from bitarray import bitarray

import HexagonArchInfo
from ImplementationException import ImplementationException
from helperFunctions import normalize_llvm_syntax


class SparseMask:
    """
    Generates the C template which extracts the Z bits of each operand.

    Bits of an operand are scattered over the encoded instruction.
    Here we assemble them by using the mask of the field.

    Simple example:
    Let the input mask of an immediate be: 0b1111111110011111111111110
    The bits of the actual immediate in the instruction encoding
    need to be concatenated ignoring bit 15:14 and bit 0 (the zeros in the example mask).
    So this function returns C-code which shifts the bits of the immediate segments and ORs them
    to represent a valid value.

    hi_u32 is the encoded instruction from which we want to concatenate bit 24:16 and bit 13:1
    (bit 31:25 are ignored here)

                 2           1
             432109876 54 3210987654321 0     indices

    Mask:    111111111|00|1111111111111|0
    hi_u32:  100111101|00|1010000010011|0
                 |                 |
                 |                 |          bit[24:16] shifted three times to the right
              +--+-----------------|------->  ((hi_u32 & 0x1ff0000) >> 3)
          ____|____                |
          1001111010000000000000   |                                   bit[13:1] shifted once to the right
    OR             1010000010011 --+---------------------------------> ((hi_u32 & 0x3ffe) >> 1))
          _______________________
    imm = 1001111011010000010011

    output:
        imm = ((hi_u32 & 0x1ff0000) >> 3) | ((hi_u32 & 0x3ffe) >> 1))

    Args:
        mask: Mask of the immediate/register
    """

    def __init__(self, mask: bitarray):
        self.full_mask = mask
        switch = False
        masks_count = 0  # How many parts the mask has
        masks = {}
        bshift = {}
        for i in range(0, 32):
            if mask[i]:
                if not switch:
                    switch = True
                    masks_count += 1
                    bshift[masks_count - 1] = i
                if masks_count - 1 in masks:
                    masks[masks_count - 1] += 1
                else:
                    masks[masks_count - 1] = 1
            else:
                switch = False

        self.masks = [(masks[i], bshift[i]) for i in range(masks_count)]

    @property
    def c_template(self):
        return ", ".join([f"{{ 0x{bits:x}, {shift} }}" for bits, shift in self.masks])


class OperandType(Enum):
    REGISTER = "HEX_OP_TYPE_REG"
    IMMEDIATE = "HEX_OP_TYPE_IMM"


class Operand:
    """
    Attributes:
        llvm_syntax: syntax of operand as found in the LLVM json (Rd32 etc.)
        explicit_syntax: str The register name: R0, C1, V14 etc.
        syntax_index: int The index in the syntax
        llvm_syntax: str The syntax of operands in the LLVM encoding object: Rd -> Rd32, #s8 -> Ii
    """

    __slots__ = [
        "explicit_syntax",
        "llvm_type",
        "llvm_syntax",
        "syntax_index",
        "is_in_operand",
        "is_out_operand",
        "is_in_out_operand",
        "type",
        "opcode_mask",
    ]

    def __init__(self, llvm_syntax: str, llvm_type: str, syntax_index: int):
        self.llvm_syntax = llvm_syntax
        self.llvm_type = llvm_type
        self.type: OperandType = self.get_operand_type(llvm_type)
        self.syntax_index = syntax_index
        self.explicit_syntax = normalize_llvm_syntax(self.llvm_syntax)
        self.opcode_mask: SparseMask = None

        self.is_in_operand = False
        self.is_out_operand = False
        self.is_in_out_operand = False

    def c_template(self, force_extendable=False) -> str:
        """Build an initializer for a HexOpTemplate struct in C, representing this operand.

        Keyword arguments:
        force_extenable -- For immediate operands, whether is_extendable should be considered
                           to be true regardless of its stored value.
        """
        raise ImplementationException("You need to override this method.")

    @staticmethod
    def get_operand_type(operand_type: str) -> OperandType:
        if operand_type in HexagonArchInfo.REG_CLASS_NAMES:
            return OperandType.REGISTER
        elif operand_type in HexagonArchInfo.IMMEDIATE_TYPES:
            return OperandType.IMMEDIATE
        else:
            raise ImplementationException("Unknown operand type: {}".format(operand_type))
