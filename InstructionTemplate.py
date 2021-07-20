# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import re

import HexagonArchInfo
import PluginInfo
from HardwareRegister import HardwareRegister
from Immediate import Immediate
from ImplementationException import ImplementationException
from InstructionEncoding import InstructionEncoding
from Operand import Operand, OperandType
from UnexpectedException import UnexpectedException
from helperFunctions import bitarray_to_uint, log, LogLevel


class InstructionTemplate:
    """Fields, flags and methods which are shared by Duplex-, Sub- and normal instructions."""

    def __init__(self, llvm_instruction):
        # Meta info
        self.llvm_instr: dict = llvm_instruction
        self.name: str = self.llvm_instr["!name"]
        self.plugin_name: str = PluginInfo.INSTR_ENUM_PREFIX + self.name.upper()
        self.type: str = self.llvm_instr["Type"]["def"]
        self.constraints = self.llvm_instr["Constraints"]
        self.has_jump_target = self.name[:2] == "J2" or self.name[:2] == "J4"
        if self.name[0] == "J" and not self.has_jump_target:
            raise ImplementationException(
                "Yet unknown jump instruction class: {}".format(self.name)
            )

        self.is_call = self.llvm_instr["isCall"] == 1
        self.is_branch = (
            self.llvm_instr["isBranch"] == 1
        )  # Not set for J2_loops, J2_trap, J2_pause
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
        self.predicated: bool = False
        self.predicate_info: bool = None

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
            llvm_syntax: The syntax for which we need the
            llvm_operands: List of operands from the llvm In/OutOperand list.

        Returns: Dictionary of {Reg_name : index} entries.
        """

        indices = dict()
        for op in llvm_operands:
            llvm_op_name = op[1]
            if llvm_op_name not in indices and llvm_op_name in llvm_syntax:
                indices[llvm_op_name] = re.search(
                    r"\b" + llvm_op_name + r"\b", llvm_syntax
                ).start()
            elif llvm_op_name in indices:
                raise UnexpectedException(
                    "Two operands with the same name given.\nSyntax {}, op: {}".format(
                        llvm_syntax, llvm_op_name
                    )
                )

        sorted_ops = dict(
            sorted(indices.items(), key=lambda item: item[1])
        )  # Sort by value
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

    # RIZIN SPECIFIC
    def get_instruction_init_in_c(self) -> str:
        """Returns one big c code block which parses one binary instruction. The blocks are used in hexagon_disas.c"""

        indent = PluginInfo.LINE_INDENT
        var = PluginInfo.HEX_INSTR_VAR_SYNTAX
        code = ""
        code += "if (({} & 0x{:x}) == 0x{:x}) {{\n".format(
            var, self.encoding.instruction_mask, self.encoding.op_code
        )
        code += "{}// {} | {}\n".format(indent, self.encoding.docs_mask, self.syntax)
        code += "{}hi->instruction = {};\n".format(indent, self.plugin_name)
        code += "{}hi->pkt_info.parse_bits = (({}) & 0x{:x}) >> 14;\n".format(
            indent, var, self.encoding.parse_bits_mask
        )
        code += "{}hi->pkt_info.loop_attr = {};\n".format(indent, self.loop_member.name)
        code += "{}hex_set_pkt_info(&(hi->pkt_info));\n".format(indent)

        if self.is_duplex:
            code += "{}hi->duplex = {};\n".format(indent, str(self.is_duplex).lower())

        # TODO Set predicate state

        code += "{}hi->op_count = {};\n".format(
            indent, self.encoding.num_encoded_operands
        )
        mnemonic = '{}sprintf(hi->mnem, "%s {} %s"'.format(indent, self.syntax)
        sprint_src = ", hi->pkt_info.syntax_prefix"

        op: Immediate
        for op in self.operands.values():
            if op.type == OperandType.IMMEDIATE and op.is_constant:
                mnemonic = re.sub(r"#[nN]1", r"#-1", mnemonic)
                continue

            code += "{}hi->ops[{}].type = {};\n".format(
                indent, op.syntax_index, op.type.value
            )

            if op.type == OperandType.REGISTER:
                code += "{}hi->ops[{}].op.reg = {}".format(
                    indent, op.syntax_index, op.code_opcode_parsing
                )
                mnemonic = re.sub(op.explicit_syntax, "%s", mnemonic)
                src = "hi->ops[{}].op.reg".format(op.syntax_index)
                sprint_src += ", {}({})".format(
                    HardwareRegister.get_func_name_of_class(op.llvm_type), src
                )

            elif op.type == OperandType.IMMEDIATE and not op.is_constant:
                code += "{}hi->ops[{}].op.imm = {}".format(
                    indent, op.syntax_index, op.code_opcode_parsing
                )

                if op.is_pc_relative:
                    src = ", addr + (st32) hi->ops[{}].op.imm".format(op.syntax_index)
                    mnemonic = re.sub(op.explicit_syntax, "0x%x", mnemonic)
                elif op.is_signed:
                    # TODO This is really complex and shouldn't be here
                    h = "#" if op.total_width != 32 else "##"
                    code += "{}if (((st32) hi->ops[{}].op.imm) < 0) {{\n".format(
                        indent, op.syntax_index
                    )
                    code += (
                        '{}sprintf(signed_imm, "%s%s0x%x", "'.format(indent * 2)
                        + h
                        + '", "-", abs((st32) hi->ops[{}].op.imm)); // Add a minus sign before hex number\n'.format(
                            op.syntax_index
                        )
                    )
                    code += "{}}}\n".format(indent)
                    code += "{}else {{\n".format(indent)

                    code += (
                        '{}sprintf(signed_imm, "%s0x%x", "'.format(indent * 2)
                        + h
                        + '", (st32) hi->ops[{}].op.imm);\n'.format(op.syntax_index)
                    )
                    code += "{}}}\n".format(indent)

                    src = ", signed_imm"
                    mnemonic = re.sub(r"#?" + op.explicit_syntax, "%s", mnemonic)
                else:
                    src = ", hi->ops[{}].op.imm".format(op.syntax_index)
                    if op.total_width == 32:
                        # 32bit values are marked with ##. Non 32bit values with #. Don't care without.
                        # Add the second # to the syntax in case of 32bit value.
                        mnemonic = re.sub(op.explicit_syntax, "#0x%x", mnemonic)
                    else:
                        mnemonic = re.sub(op.explicit_syntax, "0x%x", mnemonic)

                sprint_src += src
            else:
                raise ImplementationException("Unhandled operand: {}".format(op.syntax))

        mnemonic = self.register_names_to_upper(mnemonic)

        code += mnemonic + sprint_src + ", hi->pkt_info.syntax_postfix" + ");\n"
        if self.name == "A4_ext":
            code += "{}hex_op_extend(&(hi->ops[0]), true);\n".format(indent)
        code += "{}break;\n}}\n".format(indent)
        # log("\n" + code)

        return code

    # RIZIN SPECIFIC
    def get_rizin_op_type(self) -> str:
        op_type = "op->type = "

        if self.is_trap:
            return op_type + "RZ_ANALYSIS_OP_TYPE_TRAP"
        if not self.has_jump_target:
            return op_type + "RZ_ANALYSIS_OP_TYPE_UNK;"

        if self.predicated:
            if self.is_call:
                # Immediate and register call
                op_type += (
                    "RZ_ANALYSIS_OP_TYPE_CCALL;"
                    if self.has_imm_jmp_target()
                    else "RZ_ANALYSIS_OP_TYPE_UCCALL;"
                )
            elif self.is_return:
                op_type += "RZ_ANALYSIS_OP_TYPE_CRET;"
            elif self.is_branch or self.is_loop:
                # Immediate and register jump
                op_type += (
                    "RZ_ANALYSIS_OP_TYPE_CJMP;"
                    if self.has_imm_jmp_target()
                    else "RZ_ANALYSIS_OP_TYPE_RCJMP;"
                )
            else:
                raise ImplementationException(
                    "Instruction is not of any known branch type: {}".format(self.name)
                )
        else:
            if self.is_call:
                # Immediate and register call
                op_type += (
                    "RZ_ANALYSIS_OP_TYPE_CALL;"
                    if self.has_imm_jmp_target()
                    else "RZ_ANALYSIS_OP_TYPE_RCALL;"
                )
            elif self.is_return:
                op_type += "RZ_ANALYSIS_OP_TYPE_RET;"
            elif self.is_branch or self.is_loop:
                # Immediate and register jump
                op_type += (
                    "RZ_ANALYSIS_OP_TYPE_JMP;"
                    if self.has_imm_jmp_target()
                    else "RZ_ANALYSIS_OP_TYPE_RJMP;"
                )
            else:
                raise ImplementationException(
                    "Instruction is not of any known branch type: {}".format(self.name)
                )

        return op_type

    # RIZIN SPECIFIC
    @staticmethod
    def register_names_to_upper(mnemonic: str) -> str:
        """The syntax can contain lower case register names. Here we convert them to upper case to enable syntax
        highlighting in rizin.
        """
        for reg_name in HexagonArchInfo.ALL_REG_NAMES:
            if re.search(r"[^a-zA-Z]" + reg_name.lower(), mnemonic):
                mnemonic = re.sub(reg_name.lower(), reg_name.upper(), mnemonic)
        return mnemonic

    # RIZIN SPECIFIC
    def get_pkt_info_code(self) -> str:
        # Duplexes are always last instr. in packet.
        pass
