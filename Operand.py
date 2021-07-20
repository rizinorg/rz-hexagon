# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

from enum import Enum

from bitarray import bitarray

import HexagonArchInfo
import PluginInfo
from ImplementationException import ImplementationException
from helperFunctions import normalize_llvm_syntax


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
        "code_opcode_parsing",
        "type",
        "opcode_mask",
    ]

    def __init__(self, llvm_syntax: str, llvm_type: str, syntax_index: int):
        self.llvm_syntax = llvm_syntax
        self.llvm_type = llvm_type
        self.type: OperandType = self.get_operand_type(llvm_type)
        self.syntax_index = syntax_index
        self.explicit_syntax = normalize_llvm_syntax(self.llvm_syntax)
        self.code_opcode_parsing = ""
        self.opcode_mask: bitarray = bitarray()

        self.is_in_operand = False
        self.is_out_operand = False
        self.is_in_out_operand = False

    def add_code_for_opcode_parsing(self, parsing_code: str) -> None:
        raise ImplementationException("You need to override this method.")

    # RIZIN SPECIFIC
    @staticmethod
    def make_sparse_mask(mask: bitarray) -> str:
        """
        Generates the C code which extracts the Z bits of each operand.

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

        Returns: Returns the C code which does the bit masking + shifting.

        """

        switch = False
        ncount = 0  # counts how many bits were *not* set.
        masks_count = 0  # How many parts the mask has
        masks = {}
        bshift = {}
        for i in range(0, 32):
            if mask[i]:
                if not switch:
                    switch = True
                    masks_count += 1
                    bshift[masks_count] = ncount
                if masks_count in masks:
                    masks[masks_count] |= 1 << i
                else:
                    masks[masks_count] = 1 << i
            else:
                switch = False
                ncount += 1

        outstrings = []
        for i in range(masks_count, 0, -1):
            outstrings += [
                "((({0:s}) & 0x{1:x}) >> {2:d})".format(
                    PluginInfo.HEX_INSTR_VAR_SYNTAX, masks[i], bshift[i]
                )
            ]
        outstring = " | ".join(outstrings)
        if "|" in outstring:
            outstring = "({0:s})".format(outstring)

        # log("Generated mask C code: {}".format(outstring), LogLevel.VERBOSE)
        return outstring

    @staticmethod
    def get_operand_type(operand_type: str) -> OperandType:
        if operand_type in HexagonArchInfo.REG_CLASS_NAMES:
            return OperandType.REGISTER
        elif operand_type in HexagonArchInfo.IMMEDIATE_TYPES:
            return OperandType.IMMEDIATE
        else:
            raise ImplementationException(
                "Unknown operand type: {}".format(operand_type)
            )
