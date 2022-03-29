# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import re

from InstructionTemplate import InstructionTemplate, LoopMembership
from InstructionEncoding import InstructionEncoding
from helperFunctions import normalize_llvm_syntax, list_to_int


class Instruction(InstructionTemplate):
    """
    Definition of the instruction with the maximum processing done before being used for disassembly.
    """

    __slots__ = [
        "encoding",
        "llvm_instr",
        "i_class",
        "is_imm_ext",
        "llvm_filtered_operands",
        "mult_inst",
        "is_duplex",
        "duplex_type",
        "imm_ops",
        "reg_ops",
        "opt_ops",
        "branch",
        "behavior",
        "tokens",
        "name",
        "type",
        "syntax",
        "llvm_syntax",
        "predicated",
        "llvm_filtered_operands",
        "is_sub_instruction",
        "has_extendable_imm",
        "llvm_ext_operand_index",
        "must_be_extended",
        "extendable_alignment",
        "is_solo",
        "addr_mode",
        "access_size",
        "has_new_non_predicate",
        "llvm_new_operand_index",
    ]

    def __init__(self, llvm_instruction):
        super(Instruction, self).__init__(llvm_instruction)

        # Syntax and encoding
        self.encoding = InstructionEncoding(self.llvm_instr["Inst"])
        self.llvm_syntax = self.llvm_instr["AsmString"]
        self.syntax = normalize_llvm_syntax(self.llvm_instr["AsmString"])

        # Packet and Duplex
        # Has to be only instruction in packet.
        self.is_solo = self.llvm_instr["isSolo"][0] if "isSolo" in self.llvm_instr else None

        self.is_sub_instruction = False
        self.is_duplex = False

        # Operands
        self.num_operands = self.get_num_operands(self.llvm_syntax, self.llvm_in_out_operands)

        # Immediate operands
        self.has_extendable_imm = self.llvm_instr["isExtendable"][0] == 1
        self.must_be_extended = self.llvm_instr["isExtended"][0] == 1
        self.ext_operand_index = list_to_int(self.llvm_instr["opExtendable"])
        self.extendable_alignment = list_to_int(self.llvm_instr["opExtentAlign"])

        # Register operands
        self.has_new_non_predicate = self.llvm_instr["isNewValue"][0] == 1
        self.new_operand_index = list_to_int(self.llvm_instr["opNewValue"])
        self.is_predicated = self.llvm_instr["isPredicated"][0] == 1
        self.is_pred_false |= self.llvm_instr["isPredicatedFalse"][0] == 1
        self.is_pred_true |= self.llvm_instr["isPredicatedFalse"][0] == 0
        self.is_pred_new |= self.llvm_instr["isPredicatedNew"][0] == 1

        # Special
        self.is_endloop = "endloop" in self.name
        self.is_loop_begin = "loop" in self.name and not self.is_endloop
        self.is_loop = self.is_endloop or self.is_loop_begin
        self.loop_member = self.get_loop_membership(self.llvm_syntax)

        self.parse_instruction()

    @staticmethod
    def get_num_operands(llvm_syntax: str, llvm_operands: list) -> int:
        """Counts operands which actually appear in the syntax. This is necessary in case of
        InOutRegisters like Rx/RxIn.
        They are always listed in the LLVM instr. but not necessarily appear in the syntax.
        """
        s = 0
        for op in llvm_operands:
            name = op[1]
            s += 1 if name in llvm_syntax else 0
        return s

    @staticmethod
    def get_loop_membership(syntax: str) -> int:
        """Returns loop membership to a loop name.
        The syntax has to be parsed as some loops have the number not in the name (e.g. J2_ploop3sr).
        """
        if re.search(r"loop0[^\d]", syntax):
            return LoopMembership.HEX_LOOP_0
        elif re.search(r"loop1[^\d]", syntax):
            return LoopMembership.HEX_LOOP_1
        elif re.search(r"endloop01", syntax):
            return (
                LoopMembership.HEX_ENDS_LOOP_0
                | LoopMembership.HEX_ENDS_LOOP_1
                | LoopMembership.HEX_LOOP_0
                | LoopMembership.HEX_LOOP_1
            )
        elif re.search(r"enloop1[^\d]", syntax):
            return LoopMembership.HEX_LOOP_1 | LoopMembership.HEX_ENDS_LOOP_1
        elif re.search(r"enloop0[^\d]", syntax):
            return LoopMembership.HEX_LOOP_0 | LoopMembership.HEX_ENDS_LOOP_0
        else:
            return LoopMembership.HEX_NO_LOOP
