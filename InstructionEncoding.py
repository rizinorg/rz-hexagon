# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

from bitarray import bitarray

from helperFunctions import bitarray_to_uint
import HexagonArchInfo


class InstructionEncoding:
    """
    Represents the encoding of an instruction.

    Attributes:
        llvm_encoding: The encoding of an instruction, as it is found in an instruction object of
        the llvm-tblgen generated json file.
        docs_mask: The mask as it can be found in the Programmers Reference Manual.
        llvm_operand_names: A list of llvm type operand names which are encoded in the instruction.
        operand_masks: Masks of all operands encoded in the instruction.
        num_representation: The first 13bits of the instruction interpreted as number. Variable bits are treated as 0.
        Needed for sub instr. comparison.
        op_code: The op code as number.
        instruction_mask: The mask of the instruction.
    """

    __slots__ = [
        "docs_mask",
        "llvm_operand_names",
        "operand_masks",
        "instruction_mask",
        "llvm_encoding",
        "op_code",
        "num_representation",
        "duplex_encoding",
        "parse_bits_mask",
    ]

    def __init__(self, llvm_encoding: list):
        self.llvm_operand_names = list()
        self.operand_masks = dict()
        self.instruction_mask: int = 0
        self.op_code: int = 0
        self.parse_bits_mask: int = 0
        self.docs_mask = ""
        self.llvm_encoding = llvm_encoding
        # The first 13bit of the encoding as 13bit unsigned int. Variable fields are interpret as 0.
        self.num_representation = 0
        self.duplex_encoding = False

        self.parse_encoding()

    def parse_encoding(self):
        """Parses each bit in the LLVM encoding and extracts masks and operands from those bits."""

        instruction_mask = bitarray(HexagonArchInfo.INSTRUCTION_LENGTH, endian="little")
        instruction_mask.setall(0)
        op_code = bitarray(HexagonArchInfo.INSTRUCTION_LENGTH, endian="little")
        op_code.setall(0)
        p_bits_mask = bitarray(HexagonArchInfo.INSTRUCTION_LENGTH, endian="little")
        p_bits_mask.setall(0)

        # Bit 15:14 are only set if a duplex instruction is parsed. Else the parsing bits are None.
        if self.llvm_encoding[14] == 0 and self.llvm_encoding[15] == 0:
            self.duplex_encoding = True

        for i in range(0, 32):
            bit = self.llvm_encoding[i]
            # Instruction bits
            if bit == 0 or bit == 1:
                if i < 13:  # Number representation for SubInstruction comparison (Duplex generation).
                    self.num_representation |= bit << i

                # Parsing bits in Duplex instructions are indicated by E.
                if i == 14 or i == 15:
                    self.docs_mask = "E" + self.docs_mask
                    p_bits_mask[i] = 1
                else:
                    self.docs_mask = str(bit) + self.docs_mask

                # In the encoding of Qualcomm (see: hexagon_iset_v5.h) we can find some some irrelevant bits
                # (depicted as '-'). In the LLVM encoding they are simply set to 0. So we include them in the mask
                # and opcode anyways.
                instruction_mask[i] = 1
                op_code[i] = bit
            # The parse bits are set to null/None
            elif bit is None:
                if i == 14 or i == 15:
                    self.docs_mask = "P" + self.docs_mask
                    p_bits_mask[i] = 1
            elif bit == "-":  # Reserved bit
                self.docs_mask = "-" + self.docs_mask
            # Variable bits encoding a register or immediate
            else:
                op_name = bit["var"]
                # Not yet parsed operand in encoding found. Create new mask.
                if op_name not in self.llvm_operand_names:
                    self.llvm_operand_names.append(op_name)
                    self.operand_masks[op_name] = bitarray(HexagonArchInfo.INSTRUCTION_LENGTH, endian="little")
                    self.operand_masks[op_name].setall(0)
                self.operand_masks[op_name][i] = 1

                # We just assume that the second letter is the correct representative. Rd32 -> d, Ii -> i etc.
                self.docs_mask = op_name[1] + self.docs_mask

        self.instruction_mask = bitarray_to_uint(instruction_mask, endian="little")
        self.op_code = bitarray_to_uint(op_code, endian="little")
        self.parse_bits_mask = bitarray_to_uint(p_bits_mask, endian="little")

        # log("Added encoding: {} with operands: {}".format(self.docs_mask, self.operands), LogLevel.VERBOSE)

    def get_i_class(self) -> int:
        if self.duplex_encoding:
            enc = self.llvm_encoding
            return enc[31] << 3 | enc[30] << 2 | enc[29] << 1 | enc[13]
        else:
            i_class = self.llvm_encoding[28:32]
            return i_class[3] << 3 | i_class[2] << 2 | i_class[1] << 1 | i_class[0]
