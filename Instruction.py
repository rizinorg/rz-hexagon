# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

from copy import deepcopy
from enum import IntFlag

from Immediate import Immediate
from ImplementationException import ImplementationException
from InstructionTemplate import InstructionTemplate
from Operand import Operand, OperandType
from InstructionEncoding import InstructionEncoding
from Register import Register
from helperFunctions import *


class LoopMembership(IntFlag):
    HEX_NO_LOOP = 0
    HEX_LOOP_0 = 1
    HEX_LOOP_1 = 2
    HEX_ENDS_LOOP_0 = 4
    HEX_ENDS_LOOP_1 = 8


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
        "predicate_info",
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
        self.is_solo = (
            self.llvm_instr["isSolo"][0] if "isSolo" in self.llvm_instr else None
        )

        self.is_sub_instruction = False
        self.is_duplex = False

        # Operands
        self.num_operands = self.get_num_operands(
            self.llvm_syntax, self.llvm_in_out_operands
        )

        # Immediate operands
        self.has_extendable_imm = self.llvm_instr["isExtendable"][0] == 1
        self.must_be_extended = self.llvm_instr["isExtended"][0] == 1
        self.ext_operand_index = list_to_int(self.llvm_instr["opExtendable"])
        self.extendable_alignment = list_to_int(self.llvm_instr["opExtentAlign"])

        # Register operands
        self.has_new_non_predicate = self.llvm_instr["isNewValue"][0] == 1
        self.new_operand_index = list_to_int(self.llvm_instr["opNewValue"])
        self.predicated = self.llvm_instr["isPredicated"][0] == 1
        self.predicate_info = PredicateInfo(self.llvm_instr)

        # Special
        self.is_endloop = "endloop" in self.name
        self.is_loop_begin = "loop" in self.name and not self.is_endloop
        self.is_loop = self.is_endloop or self.is_loop_begin
        self.loop_member = self.get_loop_membership(self.llvm_syntax)

        self.parse_instruction()

    def parse_instruction(self) -> None:
        """Parses all operands of the instruction which are encoded."""

        self.llvm_filtered_operands = self.remove_invisible_in_out_regs(
            self.llvm_syntax, deepcopy(self.llvm_in_out_operands)
        )
        self.operand_indices = self.get_syntax_operand_indices(
            self.llvm_syntax, self.llvm_filtered_operands
        )

        # Update syntax indices
        if self.has_new_non_predicate:
            op_name = self.llvm_in_out_operands[self.new_operand_index][1]
            self.new_operand_index = self.operand_indices[op_name]
            # log("{}\nnew: {}".format(self.llvm_syntax, self.new_operand_index), LogLevel.DEBUG)
        if self.has_extendable_imm:
            op_name = self.llvm_in_out_operands[self.ext_operand_index][1]
            self.ext_operand_index = self.operand_indices[op_name]
            # log("{}\next: {}".format(self.llvm_syntax, self.ext_operand_index), LogLevel.DEBUG)

        if len(self.llvm_filtered_operands) > PluginInfo.MAX_OPERANDS:
            warning = "{} instruction struct can only hold {} operands. This instruction has {} operands.".format(
                PluginInfo.FRAMEWORK_NAME,
                PluginInfo.MAX_OPERANDS,
                len(self.llvm_filtered_operands),
            )
            raise ImplementationException(warning)

        # TODO Some instructions encode some register explicitly in the syntax. At the moment we do not,
        #  but maybe should add them here somehow as registers. Example: J4_cmpeq_fp0_jump_t
        #  But note that they don't seem to have an index attached to them.

        # TODO Parse high/low access of registers.

        for in_out_operand in self.llvm_filtered_operands:
            op_name = in_out_operand[1]
            op_type = in_out_operand[0]["def"]
            syntax_index = self.operand_indices[op_name]

            # Parse register operand
            if Operand.get_operand_type(op_type) is OperandType.REGISTER:
                # Indices of new values (stored in "opNewValue") are only for non predicates.
                is_new_value = (
                    self.new_operand_index == syntax_index
                    and self.has_new_non_predicate
                )
                operand = Register(op_name, op_type, is_new_value, syntax_index)
                # Whether the predicate registers holds a new value is denoted in "isPredicatedNew".
                if self.predicate_info.new_value and operand.is_predicate:
                    operand.is_new_value = True
            # Parse immediate operands
            elif Operand.get_operand_type(op_type) is OperandType.IMMEDIATE:
                extendable = (
                    self.has_extendable_imm and self.ext_operand_index == syntax_index
                )
                operand = Immediate(
                    op_name,
                    op_type,
                    extendable,
                    self.extendable_alignment,
                    syntax_index,
                )

            else:
                raise ImplementationException(
                    "Unknown operand type: {}, op_name: {}".format(op_type, op_name)
                )

            if op_name in self.constraints:
                operand.is_in_out_operand = True
                operand.is_out_operand = True
                operand.is_in_operand = True
            elif in_out_operand in self.llvm_in_operands:
                operand.is_in_operand = True
            elif in_out_operand in self.llvm_out_operands:
                operand.is_out_operand = True

            # Add opcode extraction code
            if (
                operand.type == OperandType.IMMEDIATE and operand.is_constant
            ):  # Constants have no parsing code.
                pass
            else:
                if (
                    operand.is_in_out_operand and op_name[-2:] == "in"
                ):  # In/Out Register
                    mask = self.encoding.operand_masks[op_name[:-2]]  # Ends with "in"
                else:
                    mask = self.encoding.operand_masks[op_name]
                operand.opcode_mask = mask
                operand.add_code_for_opcode_parsing(Operand.make_sparse_mask(mask))

            # On the fly check whether the new values have been assigned correctly.
            if op_name + ".new" in self.llvm_syntax:
                if not operand.is_new_value:
                    raise ImplementationException(
                        "Register has new value in syntax but not as object."
                        + "It has been parsed incorrectly! Are the indices correctly set?"
                        + "Affected instruction: {}".format(self.llvm_syntax)
                    )

            self.operands[op_name] = operand

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


class PredicateInfo:
    """Helper class to store the information about the predicate of the instruction."""

    def __init__(self, llvm_instr: dict):
        self.negative = llvm_instr["isPredicatedFalse"][0]
        self.new_value = llvm_instr["isPredicatedNew"][0]
        # What does isPredicateLate mean?
        if "isPredicateLate" in llvm_instr:
            self.late = llvm_instr["isPredicateLate"][0]
        else:
            self.late = None
