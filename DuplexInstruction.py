# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import re
from enum import IntEnum

import HexagonArchInfo
import PluginInfo
from Immediate import Immediate
from ImplementationException import ImplementationException
from Instruction import LoopMembership
from InstructionEncoding import InstructionEncoding
from InstructionTemplate import InstructionTemplate
from Operand import Operand, OperandType
from Register import Register
from SubInstruction import SubInstruction, SubInstrNamespace
from UnexpectedException import UnexpectedException
from helperFunctions import log, LogLevel, list_to_int, normalize_llvm_syntax
from copy import deepcopy


class DuplexIClass(IntEnum):
    DuplexIClass0 = 0
    DuplexIClass1 = 1
    DuplexIClass2 = 2
    DuplexIClass3 = 3
    DuplexIClass4 = 4
    DuplexIClass5 = 5
    DuplexIClass6 = 6
    DuplexIClass7 = 7
    DuplexIClass8 = 8
    DuplexIClass9 = 9
    DuplexIClassA = 10
    DuplexIClassB = 11
    DuplexIClassC = 12
    DuplexIClassD = 13
    DuplexIClassE = 14
    DuplexIClassF = 15
    INVALID = -1


class DuplexInstruction(InstructionTemplate):
    """Class represents a Duplex instruction. It is constructed out of two Sub instructions."""

    def __init__(
        self, llvm_duplex_instr: dict, low: SubInstruction, high: SubInstruction
    ):
        if llvm_duplex_instr["!name"] == "DuplexIClassF":
            raise ImplementationException("DuplexIClassF was reserved in the past.")
        super(DuplexInstruction, self).__init__(llvm_duplex_instr)
        # Qualcomm naming as in hexagon_iset_v5.h
        self.name = "X2_AUTOJOIN_" + high.name.upper() + "_" + low.name.upper()
        self.plugin_name = PluginInfo.INSTR_ENUM_PREFIX + self.name
        self.duplex_type = llvm_duplex_instr["!name"]
        self.constraints = high.constraints + " " + low.constraints

        # deepcopy() take much longer, but at least doesn't mess up our parsing algorithms
        self.low_instr = deepcopy(low)
        self.high_instr = deepcopy(high)

        self.is_duplex = True
        self.encoding = self.combine_encodings()
        self.update_syntax()

        # Order matters!
        self.llvm_in_operands = (
            self.high_instr.llvm_in_operands + self.low_instr.llvm_in_operands
        )
        # Order matters!
        self.llvm_out_operands = (
            self.high_instr.llvm_out_operands + self.low_instr.llvm_out_operands
        )
        # Order matters!
        self.llvm_in_out_operands = (
            self.high_instr.llvm_out_operands
            + self.high_instr.llvm_in_operands
            + self.low_instr.llvm_out_operands
            + self.low_instr.llvm_in_operands
        )

        # Flags
        self.set_type_flags()

        # Predicates
        self.set_duplex_predicate_info()

        # Register new values
        self.set_register_new_values()

        # Set loop info
        self.set_loop_info()

        # Immediate values
        self.set_immediate_values()

        self.parse_instruction()

        self.check_for_operand_duplicates()
        # log(self.syntax + "\n" + self.encoding.docs_mask, LogLevel.DEBUG)

    def parse_instruction(self) -> None:
        """Parses all operands of the instruction which are encoded."""

        # TODO A lot of duplicate code with Instruction::parse:instruction()
        # Operand names seen during parsing the encoding. Twin operands (Operands which appear in high and low instr.)
        # were renamed.

        all_ops = deepcopy(
            self.high_instr.llvm_in_out_operands + self.low_instr.llvm_in_out_operands
        )
        self.llvm_filtered_operands = self.remove_invisible_in_out_regs(
            self.llvm_syntax, all_ops
        )
        self.operand_indices = self.get_syntax_operand_indices(
            self.llvm_syntax, self.llvm_filtered_operands
        )

        # Update syntax indices
        if self.has_new_non_predicate:
            op_name = self.llvm_in_out_operands[self.new_operand_index][1]
            self.new_operand_index = self.operand_indices[op_name]
            # log("{}\n new: {}".format(self.llvm_syntax, self.new_operand_index), LogLevel.DEBUG)
        if self.has_extendable_imm:
            op_name = self.llvm_in_out_operands[self.ext_operand_index][1]
            self.ext_operand_index = self.operand_indices[op_name]
            # log("{}\n ext: {}".format(self.llvm_syntax, self.ext_operand_index), LogLevel.DEBUG)

        if len(self.llvm_filtered_operands) > PluginInfo.MAX_OPERANDS:
            warning = "{} instruction struct can only hold {} operands. This instruction has {} operands.".format(
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
                is_new_value = (
                    self.new_operand_index == index and self.has_new_non_predicate
                )
                operand = Register(op_name, op_type, is_new_value, index)
                # Whether the predicate registers holds a new value is denoted in "isPredicatedNew".
                if self.is_pred_new and operand.is_predicate:
                    operand.is_new_value = True

            # Parse immediate operands
            elif Operand.get_operand_type(op_type) is OperandType.IMMEDIATE:
                extendable = self.has_extendable_imm and self.ext_operand_index == index
                if self.extendable_alignment > 0:
                    log(str(self.extendable_alignment), op_type)
                operand = Immediate(
                    op_name, op_type, extendable, self.extendable_alignment, index
                )

            else:
                raise ImplementationException(
                    "Unknown operand type: {}, op_name: {}".format(op_type, op_name)
                )

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

            # log("Add operand: {}".format(op_name), LogLevel.DEBUG)
            # TODO This uses the llvm name as key. Maybe use normalized name? Rs16 -> Rs?
            self.operands[op_name] = operand

    @staticmethod
    def get_duplex_i_class_of_instr_pair(
        low: SubInstruction, high: SubInstruction
    ) -> DuplexIClass:
        """Mapping of sub instruction pairs to its Duplex class.
        Src: llvm-project/llvm/lib/Target/Hexagon/MCTargetDesc/HexagonDisassembler.cpp::getSingleInstruction()

        Args:
            low: Low sub-instruction
            high: High sub-instruction

        Returns: The Duplex class or the invalid duplex class if the instruction combination is not allowed.

        """
        if (
            low.namespace == SubInstrNamespace.SUBINSN_L1
            and high.namespace == SubInstrNamespace.SUBINSN_L1
        ):
            return DuplexIClass.DuplexIClass0
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_L2
            and high.namespace == SubInstrNamespace.SUBINSN_L1
        ):
            return DuplexIClass.DuplexIClass1
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_L2
            and high.namespace == SubInstrNamespace.SUBINSN_L2
        ):
            return DuplexIClass.DuplexIClass2
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_A
            and high.namespace == SubInstrNamespace.SUBINSN_A
        ):
            return DuplexIClass.DuplexIClass3
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_L1
            and high.namespace == SubInstrNamespace.SUBINSN_A
        ):
            return DuplexIClass.DuplexIClass4
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_L2
            and high.namespace == SubInstrNamespace.SUBINSN_A
        ):
            return DuplexIClass.DuplexIClass5
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_S1
            and high.namespace == SubInstrNamespace.SUBINSN_A
        ):
            return DuplexIClass.DuplexIClass6
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_S2
            and high.namespace == SubInstrNamespace.SUBINSN_A
        ):
            return DuplexIClass.DuplexIClass7
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_S1
            and high.namespace == SubInstrNamespace.SUBINSN_L1
        ):
            return DuplexIClass.DuplexIClass8
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_S1
            and high.namespace == SubInstrNamespace.SUBINSN_L2
        ):
            return DuplexIClass.DuplexIClass9
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_S1
            and high.namespace == SubInstrNamespace.SUBINSN_S1
        ):
            return DuplexIClass.DuplexIClassA
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_S2
            and high.namespace == SubInstrNamespace.SUBINSN_S1
        ):
            return DuplexIClass.DuplexIClassB
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_S2
            and high.namespace == SubInstrNamespace.SUBINSN_L1
        ):
            return DuplexIClass.DuplexIClassC
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_S2
            and high.namespace == SubInstrNamespace.SUBINSN_L2
        ):
            return DuplexIClass.DuplexIClassD
        elif (
            low.namespace == SubInstrNamespace.SUBINSN_S2
            and high.namespace == SubInstrNamespace.SUBINSN_S2
        ):
            return DuplexIClass.DuplexIClassE
        # DuplexIClassF is reserved
        else:
            return DuplexIClass.INVALID

    @staticmethod
    def fulfill_constraints(low: SubInstruction, high: SubInstruction) -> bool:
        """Sub-Instructions in a duplex instr have to fulfill some constraints, all of which are checked here.
        Src: llvm-project/llvm/lib/Target/Hexagon/MCTargetDesc/HexagonMCDuplexInfo.cpp::isOrderedDuplexPair
        """

        if not HexagonArchInfo.duplex_constrains_info_shown:
            log(
                "Checked Duplex constraints:"
                + "\n\t- Max. one extendable sub instruction per duplex."
                + "\n\t- Extendable instruction in slot 1 (high)."
                + "\n\t- Same sub type: smaller instruction in slot 1 (high)."
                + "\n\t- SL2_jumpr31 never in slot 1 (high)."
                + "\n\t- S2_allocframe never in slot 1 (high).",
                LogLevel.INFO,
            )
            HexagonArchInfo.duplex_constrains_info_shown = True

        # Max. one extendable sub instruction per duplex.
        # Extendable instruction in slot 1 (high)
        if low.has_extendable_imm:
            # log("low: {}, high: {} rejected because: low is extendable.".format(
            #         low.name, high.name), LogLevel.DEBUG)
            return False

        # Same sub namespace (A, S1, S2, L1, L2...): smaller instruction in slot 1 (high)
        if low.namespace == high.namespace:
            if low.encoding.num_representation < high.encoding.num_representation:
                # log("low: {}, high: {} rejected because: type is same but numerically smaller value is high.".format(
                #     low.name, high.name), LogLevel.DEBUG)
                return False

        # SL2_jumpr31[...] never in slot 1 (high)
        if "SL2_jumpr31" in high.name:
            # log("low: {}, high: {} rejected because: SL2_jumpr31 is in slot 1.".format(
            #         low.name, high.name), LogLevel.DEBUG)
            return False

        # S2_allocframe never in slot 1 (high).
        if "SS2_allocframe" in high.name:
            # log("low: {}, high: {} rejected because: S2_allocframe is in slot 1.".format(
            #         low.name, high.name), LogLevel.DEBUG)
            return False

        return True

    def combine_encodings(self) -> InstructionEncoding:
        """Combines the encoding of two sub instruction into one."""

        encoding = list([0]) * 32
        for i in range(32):
            if i < 13:  # Set bit 12:0
                encoding[i] = self.low_instr.encoding.llvm_encoding[i]
            elif i in range(16, 29):  # Set bit 28:16
                encoding[i] = self.high_instr.encoding.llvm_encoding[i - 16]
            elif i in [14, 15]:  # Parse bits are 0 in a duplex instruction.
                encoding[i] = 0

        # Set IClass
        i_class = DuplexIClass[self.duplex_type]
        encoding[13] = i_class & 1
        encoding[31] = (i_class >> 3) & 1
        encoding[30] = (i_class >> 2) & 1
        encoding[29] = (i_class >> 1) & 1
        enc = InstructionEncoding(self.correct_operand_names_in_encoding(encoding))
        # log("Name: {}\n\tDuplex:  {}\n\tSubLow:  {}\n\tSubHigh: {}\n\tIClass:  {}".format(
        #     self.name,
        #     enc.docs_mask,
        #     self.low_instr.encoding.docs_mask,
        #     self.high_instr.encoding.docs_mask,
        #     bin(i_class)
        # ), LogLevel.DEBUG)
        return enc

    def correct_operand_names_in_encoding(self, encoding_bits: list) -> list:
        """The generated duplex instructions can have multiple operands with the same name
        (e.g. high and low have both a Rs register).
        Here we change the name so it does not make problems in the following parsing.

        Note: Here we change the name _only_ in the encoding. Not in the syntax pr the self.operands field!
        """
        # Tracks all placeholder chars used by registers immediate values: d, s, t, i etc.
        low_op_chars = list()

        for i in range(0, 32):
            bit = encoding_bits[i]
            if isinstance(bit, dict):
                name = encoding_bits[i]["var"]
                char = re.search(r"[IR]([dstxi])", name).group(1)
                if char not in low_op_chars and i < 14:
                    low_op_chars.append(char)
                elif char in low_op_chars and i < 14:  # Still in lower instr.
                    continue
                elif (
                    char in low_op_chars and i > 14
                ):  # Operand with same name as in the lower instr.
                    encoding_bits[i]["var_old"] = bit["var"]  # Backup name

                    if re.search(r"R([dstx]{1,2})\d+", name):  # Register duplicate
                        pat = re.search(r"R([dstx]{1,2})\d+", name).group(1)
                        # TODO They use u and e to replace d and s letters. See: hexagon_iset_v5.h
                        replacement = pat.upper()
                        new_name = re.sub(pat, replacement, name)
                    elif re.search(r"I([i]{1,2})", name):  # Immediate duplicate
                        pat = re.search(r"I([i]{1,2})", name).group(1)
                        replacement = pat.upper()
                        new_name = re.sub(pat, replacement, name)
                    else:
                        raise ImplementationException(
                            "Unhandled double occurrence of operand"
                            + " in Duplex instruction. Operand name: {} in {}".format(
                                name, self.high_instr.llvm_syntax
                            )
                        )
                    if new_name in low_op_chars:
                        raise ImplementationException(
                            "New operand is already present in the low instruction: {}"
                            + "Please fix this method by inventing a new operand name"
                            + "(Ii -> Il or Rs -> Re maybe?)".format(new_name)
                        )

                    encoding_bits[i]["var"] = new_name
                    encoding_bits[i]["printable"] = re.sub(
                        name, new_name, encoding_bits[i]["printable"]
                    )
        return encoding_bits

    def update_syntax(self) -> None:
        """If the low and high instructions share an operand name (e.g. both have the register Rs in their syntax),
        the operand name of the high instruction has been replaced in its encoding (Rs -> RS etc.).
        Here we update the operand name in the syntax.
        """

        ops = (
            self.high_instr.llvm_instr["OutOperandList"]["args"]
            + self.high_instr.llvm_instr["InOperandList"]["args"]
        )
        operands = self.correct_not_encoded_operands(ops)

        new_high_llvm_syntax = self.high_instr.llvm_syntax
        for i in range(0, 32):
            bit = self.encoding.llvm_encoding[i]
            # Key "var_old" is only present in the variable bit, if the name has been replaced.
            if isinstance(bit, dict) and "var_old" in bit:
                if re.search(bit["var_old"], new_high_llvm_syntax):
                    # Update the syntax
                    new_high_llvm_syntax = re.sub(
                        bit["var_old"], bit["var"], new_high_llvm_syntax
                    )

                    # Update operand name in the In/OutOperands object
                    for op in operands:
                        if op[1] == bit["var_old"]:
                            op[1] = bit["var"]
                elif re.search(bit["var"], new_high_llvm_syntax):  # Already replaced
                    continue
                else:
                    raise UnexpectedException(
                        "{} not in syntax {}".format(
                            bit["var_old"], new_high_llvm_syntax
                        )
                    )

        if new_high_llvm_syntax != self.high_instr.llvm_syntax:
            # log("Changed syntax: {} -> {}\n\t{}".format(self.high_instr.llvm_syntax,
            #                                             new_high_llvm_syntax, self.encoding.llvm_encoding),
            #     LogLevel.DEBUG)
            self.high_instr.llvm_syntax = new_high_llvm_syntax
            self.high_instr.syntax = normalize_llvm_syntax(self.high_instr.llvm_syntax)
        self.llvm_syntax = (
            self.high_instr.llvm_syntax + " ; " + self.low_instr.llvm_syntax
        )
        self.syntax = normalize_llvm_syntax(self.llvm_syntax)

    def correct_not_encoded_operands(self, llvm_high_operands: list) -> list:
        """Constant immediate values are not encoded in the instruction but can occur in the low and high syntax.

        Therefore they are not renamed in correct_operand_names_in_encoding().
        Here we rename those constant operands (n1 -> N1) and update the syntax.
        Same for Rx16in register.
        """
        for op in llvm_high_operands:
            name = op[1]
            printable = op[0]["printable"]
            if op[0]["def"][-5:] != "Const" and name[-2:] != "in":
                continue
            if (
                name in self.high_instr.llvm_syntax
                and name in self.low_instr.llvm_syntax
            ):
                if name[-2:] == "in":
                    # The "in" should stay lower case. Therefore [:-2]
                    op[0]["printable"] = re.sub(
                        name[:-2], name[:-2].upper(), op[0]["printable"]
                    )
                    op[1] = name[:-2].upper() + "in"
                    self.high_instr.llvm_syntax = re.sub(
                        name, op[1], self.high_instr.llvm_syntax
                    )
                elif op[0]["def"][-5:] == "Const":
                    op[0]["printable"] = re.sub(
                        printable[:-5], printable[:-5].upper(), printable
                    )
                    op[1] = name.upper()
                    self.high_instr.llvm_syntax = re.sub(
                        name, op[1].upper(), self.high_instr.llvm_syntax
                    )
                else:
                    raise ImplementationException(
                        "Could not parse not encoded operand."
                    )
                # log("Update syntax with double constants: {}".format(self.high_instr.llvm_syntax), LogLevel.DEBUG)
        return llvm_high_operands

    def check_for_operand_duplicates(self) -> None:
        """Runtime check for duplicates of operand names (from self.operands) in the syntax."""

        for op_name in self.operands.keys():
            c = self.llvm_syntax.count(op_name)
            if op_name + "in" in self.llvm_syntax:
                c -= 1
            if c != 1:
                raise UnexpectedException(
                    "Operand has to appear exactly once in the syntax.\n"
                    + "{} appeared {} times.\nSyntax: {}\nOperands: {}".format(
                        op_name, c, self.llvm_syntax, self.operands
                    )
                )

    def set_duplex_predicate_info(self):
        """Sets the duplex instruction predicate info according to its sub instructions."""

        low = self.low_instr
        high = self.high_instr

        if low.llvm_instr["isPredicated"][0] == 1:
            self.is_predicated = True
            self.is_pred_false = low.llvm_instr["isPredicatedFalse"][0] == 1
            self.is_pred_true = low.llvm_instr["isPredicatedFalse"][0] == 0
            self.is_pred_new = low.llvm_instr["isPredicatedNew"][0] == 1
        if high.llvm_instr["isPredicated"][0] == 1:
            self.is_predicated = True
            self.is_pred_false = self.is_pred_false or (
                high.llvm_instr["isPredicatedFalse"][0] == 1
            )
            self.is_pred_true = self.is_pred_true or (
                high.llvm_instr["isPredicatedFalse"][0] == 0
            )
            self.is_pred_new = self.is_pred_new or (
                high.llvm_instr["isPredicatedNew"][0] == 1
            )

    def set_register_new_values(self):
        """Sets the duplex instruction register flags according to its sub instructions."""

        low = self.low_instr
        high = self.high_instr

        if low.has_new_non_predicate and high.has_new_non_predicate:
            raise UnexpectedException(
                "Both sub instructions have new values: {} ; {}".format(
                    low.llvm_syntax, high.llvm_syntax
                )
            )

        if low.has_new_non_predicate:
            self.has_new_non_predicate = True
            self.new_operand_index = low.new_operand_index + high.num_operands
        elif high.has_new_non_predicate:
            self.has_new_non_predicate = True
            self.new_operand_index = high.new_operand_index
        else:
            self.has_new_non_predicate = False
            self.new_operand_index = 0

    def set_immediate_values(self):
        """Sets the duplex instruction immediate flags according to its sub instructions."""

        low = self.low_instr
        high = self.high_instr

        if low.has_extendable_imm and high.has_extendable_imm:
            raise UnexpectedException(
                "Both sub instructions have extendable immediate values: {} ; {}".format(
                    low.llvm_syntax, high.llvm_syntax
                )
            )

        if low.has_extendable_imm:  # Should never occur
            raise UnexpectedException(
                "Low sub-instructions should not contain extendable values."
            )
            # self.has_extendable_imm = True
            # self.must_be_extended = low.must_be_extended
            # self.ext_operand_index = low.ext_operand_index + high.num_operands
            # self.extendable_alignment = low.extendable_alignment
        elif high.has_extendable_imm:
            self.has_extendable_imm = True
            self.must_be_extended = high.must_be_extended
            self.ext_operand_index = high.ext_operand_index
            self.extendable_alignment = high.extendable_alignment
        else:
            self.has_extendable_imm = False
            self.must_be_extended = False
            self.ext_operand_index = 0
            self.extendable_alignment = 0

    def set_loop_info(self):
        """Sets the duplex instruction loop info according to its sub instructions."""

        self.loop_member = LoopMembership.HEX_NO_LOOP
        self.is_loop_begin = False
        self.is_endloop = False
        self.is_loop = False
        if (
            self.high_instr.loop_member != LoopMembership.HEX_NO_LOOP
            and self.low_instr.loop_member != LoopMembership.HEX_NO_LOOP
        ):
            raise ImplementationException(
                "Loop instructions in high and low sub instructions are not implemented."
            )

        if self.high_instr.loop_member != LoopMembership.HEX_NO_LOOP:
            self.is_loop = self.high_instr.is_loop
            self.is_endloop = self.high_instr.is_endloop
            self.is_loop_begin = self.high_instr.is_loop_begin
            self.loop_member = self.high_instr.loop_member
        elif self.low_instr.loop_member != LoopMembership.HEX_NO_LOOP:
            self.is_loop = self.low_instr.is_loop
            self.is_endloop = self.low_instr.is_endloop
            self.is_loop_begin = self.low_instr.is_loop_begin
            self.loop_member = self.low_instr.loop_member

    def set_type_flags(self):
        """Sets all type flags of the sub instruction."""
        low = self.low_instr
        high = self.high_instr

        self.is_branch = low.is_branch or high.is_branch
        self.is_call = low.is_call or high.is_call
        self.is_pause = low.is_pause or high.is_pause
        self.is_return = low.is_return or high.is_return
        self.is_solo = low.is_solo or high.is_solo
        self.is_terminator = low.is_terminator or high.is_terminator
        self.is_trap = low.is_trap or high.is_trap
