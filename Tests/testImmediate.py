# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import unittest

from Immediate import Immediate
from Instruction import Instruction
from LLVMImporter import LLVMImporter
from helperFunctions import log, LogLevel


class TestImmediate(unittest.TestCase):
    def setUp(self) -> None:
        self.interface = LLVMImporter(False, test_mode=True, gen_rzil=False, skip_pcpp=True, rzil_compile=False)
        self.json = self.interface.hexArch

    def test_immediate_initialization(self):
        # Syntax (llvm): $Rd32 = mux($Pu4,#$Ii,#$II)
        instr = Instruction(self.json["C2_muxii"])
        imm = instr.operands["Ii"]
        self.assertTrue(imm.is_signed)
        self.assertTrue(imm.is_extendable)
        self.assertEqual(2, imm.syntax_index)
        self.assertEqual(32, imm.total_width)
        self.assertEqual(0, imm.scale)
        self.assertEqual(32, imm.encoding_width)
        self.assertEqual("s32_0Imm", imm.llvm_type)
        self.assertEqual("Ii", imm.llvm_syntax)

        imm = instr.operands["II"]
        self.assertTrue(imm.is_signed)
        self.assertFalse(imm.is_extendable)
        self.assertEqual(3, imm.syntax_index)
        self.assertEqual(8, imm.total_width)
        self.assertEqual(0, imm.scale)
        self.assertEqual(8, imm.encoding_width)
        self.assertEqual("s8_0Imm", imm.llvm_type)
        self.assertEqual("II", imm.llvm_syntax)

        # J2_jump
        instr = Instruction(self.json["J2_jump"])
        imm = instr.operands["Ii"]
        self.assertTrue(imm.is_signed)
        self.assertTrue(imm.is_extendable)
        self.assertTrue(imm.is_pc_relative)
        self.assertEqual(0, imm.syntax_index)
        self.assertEqual(32, imm.total_width)
        self.assertEqual(2, imm.scale)
        self.assertEqual(30, imm.encoding_width)
        self.assertEqual("b30_2Imm", imm.llvm_type)
        self.assertEqual("Ii", imm.llvm_syntax)

    def test_extendable_imm_coverage(self):
        for llvm_instr_name in [
            name
            for name, i in self.interface.llvm_instructions.items()
            if i["isExtendable"][0] and "OpcodeDuplex" not in i["!superclasses"]
        ]:
            c = 0
            instructions = self.interface.normal_instructions
            instructions.update(self.interface.sub_instructions)
            for op_name, op in instructions[llvm_instr_name].operands.items():
                if isinstance(op, Immediate) and op.is_extendable:
                    c += 1
            if c != 1:
                log(
                    "Extendable immediate not set in instruction: {}".format(llvm_instr_name),
                    LogLevel.ERROR,
                )
            self.assertEqual(1, c)
