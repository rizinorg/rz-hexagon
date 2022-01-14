# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import unittest

from Instruction import Instruction
from LLVMImporter import LLVMImporter


class TestRegister(unittest.TestCase):
    def setUp(self) -> None:
        self.interface = LLVMImporter(False, test_mode=True)
        self.json = self.interface.hexArch

    def test_parse_reg_type(self):
        # Syntax (llvm): "if ($Pv4) vmem($Rx32++$Mu2):nt = $Os8.new"
        instr = Instruction(self.json["V6_vS32b_nt_new_pred_ppu"])
        operand = instr.operands["Os8"]
        self.assertEqual(0, instr.operands["Pv4"].syntax_index)
        self.assertEqual(1, instr.operands["Rx32"].syntax_index)  # Rx32 is also an out operand because of the ++
        # self.assertEqual(2, instr.operands["Rx32in"].index)
        self.assertEqual(2, instr.operands["Mu2"].syntax_index)
        self.assertEqual(3, instr.operands["Os8"].syntax_index)
        self.assertEqual(3, instr.new_operand_index)
        self.assertTrue(operand.is_new_value)

        # Syntax (llvm): "if ($Pv4.new) memw($Rs32+$Ru32<<#$Ii) = $Nt8.new"
        instr = Instruction(self.json["S4_pstorerinewtnew_rr"])
        operand = instr.operands["Pv4"]
        self.assertTrue(operand.is_new_value)
        self.assertTrue(operand.is_predicate)

        operand = instr.operands["Nt8"]
        self.assertTrue(operand.is_new_value)

        self.assertEqual(0, instr.operands["Pv4"].syntax_index)
        self.assertEqual(1, instr.operands["Rs32"].syntax_index)
        self.assertEqual(2, instr.operands["Ru32"].syntax_index)
        self.assertEqual(3, instr.operands["Ii"].syntax_index)
        self.assertEqual(4, instr.operands["Nt8"].syntax_index)
