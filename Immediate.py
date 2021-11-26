# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import re

import HexagonArchInfo
import PluginInfo
from Operand import Operand
from ImplementationException import ImplementationException
from UnexpectedException import UnexpectedException
from helperFunctions import log, LogLevel


class Immediate(Operand):
    """
    The immediates stored on the instruction encoding have a smaller bit size than
    usually needed. The immediate gets extended by the processor. In the syntax
    this is denoted by a apply_extention(x).


    Args:
        syntax_index (int): The index of the immediate in the syntax.

        scale (int): Immediates which will always have a value equal to some power of 2
                      can be shifted to the right before they are encoded into the instruction
                      (which safes space). scale stores the number of bits the immediate has
                      to be shifted to the left before it is used.
    """

    __slots__ = [
        "scale",
        "type",
        "syntax",
        "is_signed",
        "is_extendable",
        "extend_alignment",
        "is_pc_relative",
        "encoding_width",
        "total_width",
        "is_constant",
    ]

    def __init__(
        self,
        llvm_syntax: str,
        llvm_type: str,
        is_extendable: bool,
        extend_alignment: int,
        syntax_index: int,
    ):
        super(Immediate, self).__init__(llvm_syntax, llvm_type, syntax_index)
        self.is_signed = False
        self.is_constant = False

        self.is_extendable = is_extendable
        self.extend_alignment = extend_alignment  # Extended immediate values are not scaled. But sometimes aligned.
        self.is_pc_relative = False

        self.scale = 0  # Num bits shifted to the left. Is set to 0 if the immediate is extendable.
        self.encoding_width = 0  # Num. bits stored in encoding.
        self.total_width = 0

        self.parse_imm_type(llvm_type)

    def parse_imm_type(self, llvm_imm_type: str) -> None:
        """Parse immediate types like: u4_2Imm. This method sets all kinds of flags, the scale and total width."""
        type_letter = re.search(r"^([a-z]+)\d{1,2}", llvm_imm_type)
        if not type_letter:
            raise ImplementationException("Unhandled immediate type: {}".format(llvm_imm_type))
        else:
            type_letter = type_letter.group(1)

        if type_letter == "s":
            self.is_signed = True
        elif type_letter == "u":
            self.is_signed = False
        # Address used in "call" and "jmp" instructions (a for call, b for jmp) is relative to PC.
        elif type_letter == "a" or type_letter == "b":
            self.is_signed = True
            self.is_pc_relative = True
        # Constant value -1
        elif type_letter == "n":
            self.is_signed = True
            self.is_constant = True
            self.encoding_width = None  # Is not encoded in the llvm instruction
            width = re.search(r"[a-z](\d+)", llvm_imm_type)
            if not width:
                raise ImplementationException("Unhandled immediate type: {}".format(llvm_imm_type))
            else:
                self.total_width = width.group(1)
            self.is_extendable = False
            # log("Parsed imm type: {}, width: {}".format(imm_type, self.total_width), LogLevel.DEBUG)
            return
        else:
            raise ImplementationException("Unhandled immediate type: {}".format(llvm_imm_type))

        # Value before _ represents number of encoded bits.
        result = re.search(r"[a-z](\d+)\_", llvm_imm_type)
        if result:
            self.encoding_width = int(result.group(1))
        else:
            raise ImplementationException("Could not parse encoding width of immediate type: {}".format(llvm_imm_type))

        # Value after the _ represents tells how often the immediate has to be shifted.
        result = re.search(r"\_(\d+)Imm", llvm_imm_type)
        if result:
            self.scale = int(result.group(1))
        else:
            raise ImplementationException("Could not find parse scale of immediate type: {}".format(llvm_imm_type))

        self.total_width = self.encoding_width + self.scale
        mx = HexagonArchInfo.MAX_IMM_LEN
        nw = int((self.total_width - mx) / 4)
        if self.total_width > mx:
            log(
                "Rizins hexagon_disas.c assumes that immediate values are not"
                " larger than {}bit.\n".format(mx)
                + "\tImmediate type: {} is {}bits long.\n".format(self.llvm_type, self.total_width)
                + "\tPlease increase the buffer hexagon_disas.c::signed_imm by"
                " at least {} bits.".format(nw),
                LogLevel.WARNING,
            )

        # The extended immediate should have always the op_type of a 32/64bit wide immediate.
        if self.is_extendable and not (self.total_width == 32 or self.total_width == 64):
            raise UnexpectedException(
                "Extendable immediate is not 32 or 64bits long!\n" + "imm: {}".format(self.llvm_syntax)
            )

    # RIZIN SPECIFIC
    def add_code_for_opcode_parsing(self, parsing_code: str) -> None:
        """Overrides method of parent class. Here we add code which does specific parsing of the operand value on
        disassembly.
        If the immediate is scaled, has specific attributes or gets extended, the c code for this is added here.
        """
        if self.is_constant:
            return

        indent = PluginInfo.LINE_INDENT
        self.code_opcode_parsing = parsing_code
        if self.scale > 0:
            self.code_opcode_parsing += " << {}; // scaled {}\n".format(self.scale, self.llvm_syntax)
            self.code_opcode_parsing += "{}hi->ops[{}].attr = HEX_OP_IMM_SCALED;\n".format(indent, self.syntax_index)
            self.code_opcode_parsing += "{}hi->ops[{}].shift = {};\n".format(indent, self.syntax_index, self.scale)
        else:
            self.code_opcode_parsing += "; // {}\n".format(self.llvm_syntax)

        if self.is_signed:
            op_bits = self.opcode_mask.count(1)
            if op_bits <= 0:
                raise ImplementationException(
                    "The bits encoding the immediate value should never be <="
                    " 0!\nOperand type: {}, Mask: {}".format(self.llvm_type, str(self.opcode_mask))
                )
            shift = (op_bits if self.scale <= 0 else op_bits + self.scale) - 1
            self.code_opcode_parsing += "{}if (hi->ops[{}].op.imm & (1 << {})) {{ // signed\n".format(
                indent, self.syntax_index, shift
            )
            self.code_opcode_parsing += "{}{}hi->ops[{}].op.imm |= (0xffffffffffffffff << {});\n{}}}\n".format(
                indent, indent, self.syntax_index, shift, indent
            )
        if self.is_extendable:
            self.code_opcode_parsing += (
                "{}hex_extend_op(state, &(hi->ops[{}]), false, addr); //"
                " Extension possible\n".format(indent, self.syntax_index)
            )
