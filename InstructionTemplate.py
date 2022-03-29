# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

from copy import deepcopy
from enum import IntFlag
import re

import HexagonArchInfo
import PluginInfo
from Immediate import Immediate
from ImplementationException import ImplementationException
from InstructionEncoding import InstructionEncoding
from Operand import Operand, OperandType, SparseMask
from Register import Register
from UnexpectedException import UnexpectedException
from helperFunctions import log, LogLevel

PARSE_BITS_MASK_CONST = 0xc000  # currently, this is the same for all instructions, so no need to store it explicitly


class LoopMembership(IntFlag):
    HEX_NO_LOOP = 0
    HEX_LOOP_0 = 1
    HEX_LOOP_1 = 2
    HEX_ENDS_LOOP_0 = 4
    HEX_ENDS_LOOP_1 = 8


class InstructionTemplate:
    """Fields, flags and methods which are shared by Duplex-, Sub- and normal instructions."""

    def __init__(self, llvm_instruction):
        # Meta info
        self.llvm_instr: dict = llvm_instruction
        self.name: str = self.llvm_instr["!name"]
        self.is_vector = self.name[0] == "V"
        self.plugin_name: str = PluginInfo.INSTR_ENUM_PREFIX + self.name.upper()
        self.type: str = self.llvm_instr["Type"]["def"]
        self.constraints = self.llvm_instr["Constraints"]
        self.has_jump_target = self.name[:2] == "J2" or self.name[:2] == "J4"
        if self.name[0] == "J" and not self.has_jump_target:
            raise ImplementationException("Yet unknown jump instruction class: {}".format(self.name))

        self.is_call = self.llvm_instr["isCall"] == 1
        self.is_branch = self.llvm_instr["isBranch"] == 1  # Not set for J2_loops, J2_trap, J2_pause
        self.is_terminator = self.llvm_instr["isTerminator"] == 1
        self.is_return = self.llvm_instr["isReturn"] == 1
        # The parsing bits are not set in the encoding. Therefore we simply do this search.
        self.is_pause = self.name == "J2_pause"
        self.is_trap = "trap" in self.name
        if self.is_trap or self.is_pause:
            self.has_jump_target = False

        # Syntax and encoding
        self.encoding: InstructionEncoding = None
        self.llvm_syntax: str = None
        self.syntax: str = None

        # Packet and Duplex
        # Has to be only instruction in packet.
        self.is_solo: bool = None

        self.is_sub_instruction: bool = None
        self.is_duplex: bool = None

        # Operands
        self.llvm_in_operands: list = self.llvm_instr["InOperandList"]["args"]
        self.llvm_out_operands: list = self.llvm_instr["OutOperandList"]["args"]
        # Order matters!
        self.llvm_in_out_operands: list = self.llvm_out_operands + self.llvm_in_operands
        self.llvm_filtered_operands: list = list()
        self.operands = dict()
        self.operand_indices = dict()
        self.num_operands = 999
        self.llvm_operands = list()
        self.new_operand_index = 999
        self.ext_operand_index = 999

        # Immediate operands
        self.has_extendable_imm: bool = None
        self.must_be_extended: bool = None
        self.llvm_ext_operand_index: bool = None
        self.extendable_alignment: bool = None

        # Register operands
        self.has_new_non_predicate: bool = None
        self.llvm_new_operand_index: bool = None
        self.is_predicated: bool = False
        self.is_pred_new: bool = False
        self.is_pred_false: bool = False  # Duplex can have both, true and false predicates.
        self.is_pred_true: bool = False

        # Special
        self.is_imm_ext: bool = self.type == "TypeEXTENDER"
        self.is_endloop: bool = None
        self.is_loop: bool = None
        self.is_loop_begin: bool = None
        self.loop_member = None

        # Execution specific (Interesting for decompiler plugin)
        # The address mode of load/store instructions
        self.addr_mode = None
        # The access size of the load/store instruction
        self.access_size = None

    def assign_syntax_indices_to_operands(self) -> None:
        pass

    @staticmethod
    def get_syntax_operand_indices(llvm_syntax: str, llvm_operands: list) -> dict:
        """Gives the indices of the operands in the syntax, counted from left to right.

            LLVM indexing starts counting from the out-operands to the in-operands json objects.
            If a Rx register is used in the syntax the position of the Register in the syntax does not represent the
            index of the operand. Because there are always an Rx and RxIn operand in json. But RxIn is not necessarily
            shown in the syntax (E.g. for Rx++).
            This is why we here create our own indices.
            See the test case for: V6_vS32b_nt_new_pred_ppu

        Args:
            llvm_syntax: The llvm syntax string.
            llvm_operands: List of operands from the llvm In/OutOperand list.

        Returns: Dictionary of {Reg_name : index} entries.
        """

        indices = dict()
        for op in llvm_operands:
            llvm_op_name = op[1]
            if llvm_op_name not in indices and llvm_op_name in llvm_syntax:
                indices[llvm_op_name] = re.search(r"\b" + llvm_op_name + r"\b", llvm_syntax).start()
            elif llvm_op_name in indices:
                raise UnexpectedException(
                    "Two operands with the same name given.\nSyntax {}, op: {}".format(llvm_syntax, llvm_op_name)
                )

        sorted_ops = dict(sorted(indices.items(), key=lambda item: item[1]))  # Sort by value
        for i, operand_name in enumerate(sorted_ops):
            indices[operand_name] = i

        return indices

    @staticmethod
    def remove_invisible_in_out_regs(llvm_syntax: str, llvm_ops: list) -> list:
        """Removes registers from the llvm_ops list which does not appear in the syntax."""
        del_indices = list()
        for i, op in enumerate(llvm_ops):
            name = op[1]
            if name not in llvm_syntax:
                del_indices.append(i)

        for n, i in enumerate(del_indices):
            del llvm_ops[i - n]
        return llvm_ops

    def has_imm_jmp_target(self) -> bool:
        """Returns true if the call or jump uses a immediate value to determine the target address. Otherwise false"""

        if self.has_jump_target:
            op: Operand
            for op in self.operands.values():
                if op.type == OperandType.IMMEDIATE:
                    op: Immediate
                    if op.is_pc_relative:
                        return True
                    elif len(self.operands) == 1:
                        return True  # Assume true if it is the only operand.
        return False

    def get_jmp_operand_syntax_index(self) -> int:
        """Returns the index of the operand in the syntax or -1 if no PC relative operand exists."""
        for op in self.operands.values():
            if op.type != OperandType.IMMEDIATE:
                continue
            if op.is_pc_relative:
                return op.syntax_index
            elif len(self.operands) == 1:
                return op.syntax_index  # If it is the only operand it is the address.

        return -1

    def parse_instruction(self) -> None:
        """Parses all operands of the instruction which are encoded."""

        if self.is_duplex:
            all_ops = deepcopy(self.high_instr.llvm_in_out_operands + self.low_instr.llvm_in_out_operands)
        else:
            all_ops = deepcopy(self.llvm_in_out_operands)

        self.llvm_filtered_operands = self.remove_invisible_in_out_regs(self.llvm_syntax, all_ops)
        self.operand_indices = self.get_syntax_operand_indices(self.llvm_syntax, self.llvm_filtered_operands)

        # Update syntax indices.
        if self.has_new_non_predicate:
            op_name = self.llvm_in_out_operands[self.new_operand_index][1]
            self.new_operand_index = self.operand_indices[op_name]
            log("{}\n new: {}".format(self.llvm_syntax, self.new_operand_index), LogLevel.VERBOSE)
        if self.has_extendable_imm:
            op_name = self.llvm_in_out_operands[self.ext_operand_index][1]
            self.ext_operand_index = self.operand_indices[op_name]
            log("{}\n ext: {}".format(self.llvm_syntax, self.ext_operand_index), LogLevel.VERBOSE)

        if len(self.llvm_filtered_operands) > PluginInfo.MAX_OPERANDS:
            warning = "{} instruction struct can only hold {} operands. This" " instruction has {} operands.".format(
                PluginInfo.FRAMEWORK_NAME,
                PluginInfo.MAX_OPERANDS,
                len(self.llvm_filtered_operands),
            )
            raise ImplementationException(warning)

        for in_out_operand in self.llvm_filtered_operands:
            op_name = in_out_operand[1]
            op_type = in_out_operand[0]["def"]
            index = self.operand_indices[op_name]

            # Parse register operand
            if Operand.get_operand_type(op_type) is OperandType.REGISTER:
                # Indices of new values (stored in "opNewValue") are only for non predicates.
                is_new_value = self.new_operand_index == index and self.has_new_non_predicate
                operand = Register(op_name, op_type, is_new_value, index)
                # Whether the predicate registers holds a new value is denoted in "isPredicatedNew".
                if self.is_pred_new and operand.is_predicate:
                    operand.is_new_value = True

            # Parse immediate operands
            elif Operand.get_operand_type(op_type) is OperandType.IMMEDIATE:
                extendable = self.has_extendable_imm and self.ext_operand_index == index
                operand = Immediate(
                    op_name,
                    op_type,
                    extendable,
                    self.extendable_alignment,
                    index,
                )

            else:
                raise ImplementationException("Unknown operand type: {}, op_name: {}".format(op_type, op_name))

            # Use lower() because we can get RX16in and Rx16in but constraints are always Rx16in.
            if op_name.lower() in self.constraints.lower():
                operand.is_in_out_operand = True
                operand.is_out_operand = True
                operand.is_in_operand = True
            elif in_out_operand in self.llvm_in_operands:
                operand.is_in_operand = True
            elif in_out_operand in self.llvm_out_operands:
                operand.is_out_operand = True

            # Add opcode extraction code
            if operand.type == OperandType.IMMEDIATE and operand.is_constant:  # Constants have no parsing code.
                pass
            else:
                if operand.is_in_out_operand and op_name[-2:] == "in":  # In/Out Register
                    mask = self.encoding.operand_masks[op_name[:-2]]  # Ends with "in"
                else:
                    mask = self.encoding.operand_masks[op_name]
                operand.opcode_mask = SparseMask(mask)
            # On the fly check whether the new values have been assigned correctly.
            if op_name + ".new" in self.llvm_syntax:
                if not operand.is_new_value:
                    raise ImplementationException(
                        "Register has new value in syntax but not as object."
                        + "It has been parsed incorrectly! Are the indices"
                        " correctly set?" + "Affected instruction: {}".format(self.llvm_syntax)
                    )

            self.operands[op_name] = operand

    def get_template_in_c(self) -> str:
        """Returns an initializer for the HexInsnTemplate struct representing this instruction"""
        code = "{\n"
        code += f"// {self.encoding.docs_mask} | {self.syntax}\n"
        code += f".encoding = {{ .mask = 0x{self.encoding.instruction_mask:x}, .op = 0x{self.encoding.op_code:x} }},\n"
        code += f".id = {self.plugin_name},\n"
        if self.encoding.parse_bits_mask != PARSE_BITS_MASK_CONST:
            raise ImplementationException(
                f"Unknown parse_bits_mask {self.encoding.parse_bits_mask} != {PARSE_BITS_MASK_CONST}")
        op_templates = []
        last_syntax_off = 0
        syntax = self.syntax
        only_one_imm_op = 1 == len([op for op in self.operands.values() if op.type == OperandType.IMMEDIATE])
        for op in sorted(self.operands.values(), key=lambda item: item.syntax_index):
            if op.type == OperandType.IMMEDIATE and op.is_constant:
                pattern = r"[nN]1"
            else:
                pattern = op.explicit_syntax
            inject = re.search(pattern, syntax)
            if inject is None:
                raise ImplementationException(f"Operand pattern {pattern} not found in syntax {syntax}")
            elif inject.start() < last_syntax_off:
                raise ImplementationException(f"Operand pattern {pattern} in syntax {syntax} out of order")
            syntax_off = inject.start()
            syntax = syntax[:inject.start()] + syntax[inject.end():]
            last_syntax_off = syntax_off
            tpl = f"{{ {op.c_template(force_extendable=only_one_imm_op)}, .syntax = {syntax_off} }}"
            op_templates.append(tpl)
        syntax = self.register_names_to_upper(syntax)
        if len(op_templates) != 0:
            ops_code = ",\n".join(op_templates)
            code += f".ops = {{\n{ops_code}, }},\n"
        code += f".pred = {self.get_predicate()},"
        code += f".cond = {self.get_rz_cond_type()},\n"
        code += f".type = {self.c_rz_op_type},\n"
        code += f".syntax = \"{syntax}\",\n"
        flags = []
        if self.is_call:
            flags.append("HEX_INSN_TEMPLATE_FLAG_CALL")
        if self.is_predicated:
            flags.append("HEX_INSN_TEMPLATE_FLAG_PREDICATED")
        if self.has_jump_target:
            flags.append("HEX_INSN_TEMPLATE_FLAG_HAS_JMP_TGT")
        if self.is_loop_begin:
            flags.append("HEX_INSN_TEMPLATE_FLAG_LOOP_BEGIN")
        if self.loop_member == LoopMembership.HEX_LOOP_0:
            flags.append("HEX_INSN_TEMPLATE_FLAG_LOOP_0")
        elif self.loop_member == LoopMembership.HEX_LOOP_1:
            flags.append("HEX_INSN_TEMPLATE_FLAG_LOOP_1")
        if flags != []:
            flags = " | ".join(flags)
            code += f".flags = {flags},\n"
        code += "}"
        return code

    # RIZIN SPECIFIC
    def get_predicate(self) -> str:
        if not self.is_predicated:
            pred = ["HEX_NOPRED"]
        else:
            pred = []
            if self.is_pred_false:
                pred.append("HEX_PRED_FALSE")
            if self.is_pred_true:
                pred.append("HEX_PRED_TRUE")
            if self.is_pred_new:
                pred.append("HEX_PRED_NEW")
        return " | ".join(pred)

    # RIZIN SPECIFIC
    def get_rz_cond_type(self):
        """Returns the rizin conditional type."""

        if not self.is_predicated:
            return "RZ_TYPE_COND_AL"

        if self.is_vector:
            if self.is_pred_true:
                return "RZ_TYPE_COND_HEX_VEC_TRUE"
            else:
                return "RZ_TYPE_COND_HEX_VEC_FALSE"
        else:
            if self.is_pred_true:
                return "RZ_TYPE_COND_HEX_SCL_TRUE"
            else:
                return "RZ_TYPE_COND_HEX_SCL_FALSE"

    # RIZIN SPECIFIC
    @property
    def c_rz_op_type(self) -> str:
        if self.is_trap:
            return "RZ_ANALYSIS_OP_TYPE_TRAP"
        elif self.name == "A2_nop":
            return "RZ_ANALYSIS_OP_TYPE_NOP"
        elif self.name == "invalid_decode":
            return "RZ_ANALYSIS_OP_TYPE_ILL"

        if self.is_predicated:
            if self.is_call:
                # Immediate and register call
                return "RZ_ANALYSIS_OP_TYPE_CCALL" if self.has_imm_jmp_target() else "RZ_ANALYSIS_OP_TYPE_UCCALL"
            elif self.is_return:
                return "RZ_ANALYSIS_OP_TYPE_CRET"
            elif self.is_branch or self.is_loop:
                # Immediate and register jump
                if self.has_imm_jmp_target():
                    return "RZ_ANALYSIS_OP_TYPE_CJMP"
                else:
                    return "RZ_ANALYSIS_OP_TYPE_RCJMP"
            else:
                return "RZ_ANALYSIS_OP_TYPE_COND"
        else:
            if self.is_call:
                # Immediate and register call
                return "RZ_ANALYSIS_OP_TYPE_CALL" if self.has_imm_jmp_target() else "RZ_ANALYSIS_OP_TYPE_RCALL"
            elif self.is_return:
                return "RZ_ANALYSIS_OP_TYPE_RET"
            elif self.is_branch or self.is_loop:
                # Immediate and register jump
                return "RZ_ANALYSIS_OP_TYPE_JMP" if self.has_imm_jmp_target() else "RZ_ANALYSIS_OP_TYPE_RJMP"
        log(
            "Instruction: {} has no instr. type assigned to it yet.".format(self.name),
            LogLevel.VERBOSE,
        )
        return "RZ_ANALYSIS_OP_TYPE_NULL"

    # RIZIN SPECIFIC
    @staticmethod
    def register_names_to_upper(mnemonic: str) -> str:
        """The syntax can contain lower case register names. Here we convert them to upper case to enable syntax
        highlighting in rizin.
        """
        for reg_name in HexagonArchInfo.ALL_REG_NAMES:
            if re.search(r"[^a-zA-Z]" + reg_name.lower(), mnemonic) or mnemonic.startswith(reg_name.lower()):
                mnemonic = re.sub(reg_name.lower(), reg_name.upper(), mnemonic)
        return mnemonic

    # RIZIN SPECIFIC
    def get_pkt_info_code(self) -> str:
        # Duplexes are always last instr. in packet.
        pass
