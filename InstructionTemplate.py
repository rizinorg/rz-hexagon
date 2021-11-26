# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

from enum import IntFlag
import re

import HexagonArchInfo
import PluginInfo
import Register
from HardwareRegister import HardwareRegister
from Immediate import Immediate
from ImplementationException import ImplementationException
from InstructionEncoding import InstructionEncoding
from Operand import Operand, OperandType
from UnexpectedException import UnexpectedException
from helperFunctions import log, LogLevel


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
            llvm_syntax: The syntax for which we need the
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

    # RIZIN SPECIFIC
    def get_instruction_init_in_c(self) -> str:
        """Returns one big c code block which parses one binary instruction. The blocks are used in hexagon_disas.c"""

        only_one_imm_op = 1 == len([op for op in self.operands.values() if op.type == OperandType.IMMEDIATE])

        indent = PluginInfo.LINE_INDENT
        var = PluginInfo.HEX_INSTR_VAR_SYNTAX
        code = ""
        code += "if (({} & 0x{:x}) == 0x{:x}) {{\n".format(
            var,
            self.encoding.instruction_mask,
            self.encoding.op_code,
        )
        code += "// {} | {}\n".format(self.encoding.docs_mask, self.syntax)
        code += "hi->instruction = {};\n".format(self.plugin_name)
        code += "hi->opcode = hi_u32;\n"
        code += "hi->parse_bits = (({}) & 0x{:x}) >> 14;\n".format(var, self.encoding.parse_bits_mask)
        code += self.get_predicate_init()

        if self.is_duplex:
            code += "{}hi->duplex = {};\n".format(indent, str(self.is_duplex).lower())

        code += "{}hi->op_count = {};\n".format(indent, self.encoding.num_encoded_operands)
        mnemonic = 'sprintf(hi->mnem_infix, "{}"'.format(self.syntax)
        sprint_src = ""
        for op in sorted(self.operands.values(), key=lambda item: item.syntax_index):
            if op.type == OperandType.IMMEDIATE and op.is_constant:
                mnemonic = re.sub(r"[nN]1", r"-1", mnemonic)
                continue

            code += "{}hi->ops[{}].type = {};\n".format(indent, op.syntax_index, op.type.value)

            if op.type == OperandType.REGISTER:
                op: Register
                code += "{}hi->ops[{}].op.reg = {}".format(indent, op.syntax_index, op.code_opcode_parsing)
                if op.is_out_operand:
                    code += "hi->ops[{}].attr |= HEX_OP_REG_OUT;\n".format(op.syntax_index)
                if op.is_double:
                    code += "hi->ops[{}].attr |= HEX_OP_REG_PAIR;\n".format(op.syntax_index)
                if op.is_quadruple:
                    code += "hi->ops[{}].attr |= HEX_OP_REG_QUADRUPLE;\n".format(op.syntax_index)

                mnemonic = re.sub(op.explicit_syntax, "%s", mnemonic)
                src = "hi->ops[{}].op.reg".format(op.syntax_index)
                if op.is_n_reg:
                    sprint_src += ", {}({}({}, hi->addr, pkt))".format(
                        HardwareRegister.get_func_name_of_class(op.llvm_type, False),
                        HardwareRegister.get_func_name_of_class(op.llvm_type, True),
                        src,
                    )
                else:
                    sprint_src += ", {}({})".format(
                        HardwareRegister.get_func_name_of_class(op.llvm_type, False),
                        src,
                    )

            elif op.type == OperandType.IMMEDIATE and not op.is_constant:
                code += "{}hi->ops[{}].op.imm = {}".format(indent, op.syntax_index, op.code_opcode_parsing)
                h = "#" if op.total_width != 32 else "##"
                # If there is only one immediate operand in the instruction extend it anyways.
                # LLVM marks some operands as not extendable, although they are.
                if only_one_imm_op and not op.is_extendable:
                    code += (
                        "hex_extend_op(state, &(hi->ops[{}]), false, addr); //"
                        " Only immediate, extension possible\n".format(op.syntax_index)
                    )

                if op.is_pc_relative:
                    src = ", pkt->pkt_addr + (st32) hi->ops[{}].op.imm".format(op.syntax_index)
                    mnemonic = re.sub(op.explicit_syntax, "0x%x", mnemonic)
                elif op.is_signed:
                    code += "if (rz_asm->immsign && ((st32) hi->ops[{}].op.imm) <" " 0) {{\n".format(op.syntax_index)
                    code += (
                        "char tmp[28] = {0};"
                        + "rz_hex_ut2st_str(hi->ops[{}].op.imm, tmp, 28);".format(op.syntax_index)
                        + 'sprintf(signed_imm[{}], "%s%s", '.format(op.syntax_index)
                        + '!rz_asm->immdisp ? "'
                        + h
                        + '" : "", '
                        + "tmp);"
                    )
                    code += "} else {\n"

                    code += (
                        'sprintf(signed_imm[{}], "%s0x%x", '.format(op.syntax_index)
                        + '!rz_asm->immdisp ? "'
                        + h
                        + '" : "", '
                        + "(st32) hi->ops[{}].op.imm);\n".format(op.syntax_index)
                    )
                    code += "}\n"

                    src = ", signed_imm[{}]".format(op.syntax_index)
                    mnemonic = re.sub(r"#{0,2}" + op.explicit_syntax, "%s", mnemonic)
                else:
                    mnemonic = re.sub(op.explicit_syntax, "%s0x%x", mnemonic)
                    src = ', !rz_asm->immdisp ? "' + h + '" : "" ,(ut32) hi->ops[{}].op.imm'.format(op.syntax_index)

                sprint_src += src
            else:
                raise ImplementationException("Unhandled operand: {}".format(op.syntax))

        code += self.get_analysis_code()
        mnemonic = self.register_names_to_upper(mnemonic)

        code += mnemonic + sprint_src + ");\n"
        code += (
            'sprintf(hi->mnem, "%s%s%s", hi->pkt_info.syntax_prefix,' " hi->mnem_infix, hi->pkt_info.syntax_postfix);\n"
        )
        if self.name == "A4_ext":
            code += "{}hex_extend_op(state, &(hi->ops[0]), true, addr);\n".format(indent)
        code += "{}return;\n}}\n".format(indent)
        # log("\n" + code)

        return code

    # RIZIN SPECIFIC
    def get_analysis_code(self):
        code = "// Set RzAnalysisOp values\n"
        code += "hi->ana_op.addr = hi->addr;\n"
        code += "hi->ana_op.id = hi->instruction;\n"
        code += "hi->ana_op.size = 4;\n"
        code += self.get_rizin_op_type()
        if self.has_imm_jmp_target():
            if not self.is_call and not self.is_predicated:
                code += "pkt->is_eob = true;\n"  # Marks potentially end of block

            index = self.get_jmp_operand_syntax_index()
            if index < 0:
                raise ImplementationException(
                    "No PC relative operand given. But the jump needs one." "{}".format(self.llvm_syntax)
                )

            code += "hi->ana_op.jump = pkt->pkt_addr + (st32)" " hi->ops[{}].op.imm;\n".format(index)
            if self.is_predicated:
                code += "hi->ana_op.fail = hi->ana_op.addr + 4;\n"
            if self.is_loop_begin:
                if self.loop_member == LoopMembership.HEX_LOOP_0:
                    code += "pkt->hw_loop0_addr = hi->ana_op.jump;"
                if self.loop_member == LoopMembership.HEX_LOOP_1:
                    code += "pkt->hw_loop1_addr = hi->ana_op.jump;"

        keys = list(self.operands)
        for k in range(6):  # RzAnalysisOp.analysis_vals has a size of 8.
            if k < len(self.operands.values()):
                o = self.operands[keys[k]]
                if self.has_imm_jmp_target() and o.type == OperandType.IMMEDIATE:
                    code += "hi->ana_op.val = hi->ana_op.jump;\n"
                    code += "hi->ana_op.analysis_vals[{}].imm = hi->ana_op.jump;\n".format(o.syntax_index)
                else:
                    if o.type == OperandType.IMMEDIATE:
                        code += "hi->ana_op.analysis_vals[{si}].imm =" " hi->ops[{si}].op.imm;\n".format(
                            si=o.syntax_index
                        )

        return code

    # RIZIN SPECIFIC
    def get_predicate_init(self) -> str:
        code = "hi->pred = "
        if not self.is_predicated:
            code += "HEX_NOPRED;\n"
            return code

        if self.is_pred_false:
            code += "| HEX_PRED_FALSE"
        if self.is_pred_true:
            code += "| HEX_PRED_TRUE"
        if self.is_pred_new:
            code += "| HEX_PRED_NEW"
        if "= |" in code:
            code = re.sub(r"= \|", "= ", code)
        code += ";\n"
        return code

    # RIZIN SPECIFIC
    def get_rizin_op_type(self) -> str:
        """Returns the c code to assign the instruction type to the RzAnalysisOp.type member."""

        op_type = "hi->ana_op.type |= "

        if self.is_trap:
            return op_type + "RZ_ANALYSIS_OP_TYPE_TRAP;"
        elif self.name == "A2_nop":
            return op_type + "RZ_ANALYSIS_OP_TYPE_NOP;"
        elif self.name == "invalid_decode":
            return op_type + "RZ_ANALYSIS_OP_TYPE_ILL;"

        if self.is_predicated:
            if self.is_call:
                # Immediate and register call
                op_type += "RZ_ANALYSIS_OP_TYPE_CCALL;" if self.has_imm_jmp_target() else "RZ_ANALYSIS_OP_TYPE_UCCALL;"
            elif self.is_return:
                op_type += "RZ_ANALYSIS_OP_TYPE_CRET;"
            elif self.is_branch or self.is_loop:
                # Immediate and register jump
                op_type += "RZ_ANALYSIS_OP_TYPE_CJMP;" if self.has_imm_jmp_target() else "RZ_ANALYSIS_OP_TYPE_RCJMP;"
            else:
                op_type += "RZ_ANALYSIS_OP_TYPE_COND;"
        else:
            if self.is_call:
                # Immediate and register call
                op_type += "RZ_ANALYSIS_OP_TYPE_CALL;" if self.has_imm_jmp_target() else "RZ_ANALYSIS_OP_TYPE_RCALL;"
            elif self.is_return:
                op_type += "RZ_ANALYSIS_OP_TYPE_RET;"
            elif self.is_branch or self.is_loop:
                # Immediate and register jump
                op_type += "RZ_ANALYSIS_OP_TYPE_JMP;" if self.has_imm_jmp_target() else "RZ_ANALYSIS_OP_TYPE_RJMP;"

        if op_type == "hi->ana_op.type |= ":
            log(
                "Instruction: {} has no instr. type assigned to it yet.".format(self.name),
                LogLevel.VERBOSE,
            )
            return op_type + "RZ_ANALYSIS_OP_TYPE_NULL;"

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
