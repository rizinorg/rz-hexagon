# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import unittest

from InstructionTemplate import InstructionTemplate
from UnexpectedException import UnexpectedException
from helperFunctions import normalize_llvm_syntax


class TestInstruction(unittest.TestCase):

    # TODO Indices for: V6_vS32b_nt_new_pred_ppu: "if ($Pv4) vmem($Rx32++$Mu2):nt = $Os8.new"

    # TODO
    #  - actual vs. theoretical new operands, also predicates
    #  - Actual vs. theoretical indices
    #  - Operand attributes (new, extendable)
    #  - Op-type and scale values etc
    #  - Names
    #  - Rx and Rxin register

    def test_normalize_llvm_syntax(self) -> None:
        self.assertEqual(
            "Rdd = add(Rs,Rtt)",
            normalize_llvm_syntax("$Rdd32 = add($Rs32,$Rtt32)"),
        )
        self.assertEqual(
            "RDD = add(RS,RTT)",
            normalize_llvm_syntax("$RDD32 = add($RS32,$RTT32)"),
        )
        self.assertEqual(
            "Vxx.w += vmpy(Vu.h,Vv.h)",
            normalize_llvm_syntax("$Vxx32.w += vmpy($Vu32.h,$Vv32.h)"),
        )
        self.assertEqual(
            "Rd = add(Rt.h,Rs.h):<<16",
            normalize_llvm_syntax("$Rd32 = add($Rt32.h,$Rs32.h):<<16"),
        )
        self.assertEqual(
            "if (!Pu) Rd = add(Rs,Rt)",
            normalize_llvm_syntax("if (!$Pu4) $Rd32 = add($Rs32,$Rt32)"),
        )
        # Specifically named registers
        self.assertEqual(
            "if (p0.new) dealloc_return:nt",
            normalize_llvm_syntax("if (p0.new) dealloc_return:nt"),
        )
        self.assertEqual(
            "if (!p0.new) jumpr:nt r31",
            normalize_llvm_syntax("if (!p0.new) jumpr:nt r31"),
        )
        # Duplex
        self.assertEqual(
            "Rx = add(Rxin,II) ; Rd = memw(Rs+Ii)",
            normalize_llvm_syntax("$Rx16 = add($Rx16in,#$II) ; $Rd16 = memw($Rs16+#$Ii)"),
        )

    def test_get_syntax_operand_indices(self) -> None:
        syntax = "$RDD8 = combine($RS16,#0) ; $Rd16 = add($Rs16,#$n1)"
        operands = [
            ["", "Rd16"],
            ["", "Rs16"],
            ["", "RDD8"],
            ["", "RS16"],
            ["", "n1"],
        ]
        correct_order = {"RDD8": 0, "RS16": 1, "Rd16": 2, "Rs16": 3, "n1": 4}
        self.assertEqual(
            correct_order,
            InstructionTemplate.get_syntax_operand_indices(syntax, operands),
        )

        syntax = "$Rd32 = add($Rs32,#$Ii)"
        operands = [["", "Rd32"], ["", "Ii"], ["", "Rs32"]]
        correct_order = {"Rd32": 0, "Rs32": 1, "Ii": 2}
        self.assertEqual(
            correct_order,
            InstructionTemplate.get_syntax_operand_indices(syntax, operands),
        )

        syntax = "$Rx16 = add($Rx16in,#$II) ; $Rd16 = memw($Rs16+#$Ii)"
        operands = [
            ["", "Rx16"],
            ["", "Rx16in"],
            ["", "II"],
            ["", "Rd16"],
            ["", "Rs16"],
            ["", "Ii"],
        ]
        correct_order = {
            "Rx16": 0,
            "Rx16in": 1,
            "II": 2,
            "Rd16": 3,
            "Rs16": 4,
            "Ii": 5,
        }
        self.assertEqual(
            correct_order,
            InstructionTemplate.get_syntax_operand_indices(syntax, operands),
        )

        syntax = "$Rd32 = add($Rs32,#$Ii)"
        operands = [["", "Ii"], ["", "Ii"], ["", "Rs32"]]
        with self.assertRaises(UnexpectedException) as context:
            InstructionTemplate.get_syntax_operand_indices(syntax, operands)
        self.assertTrue(
            "Two operands with the same name given.\n" + "Syntax $Rd32 = add($Rs32,#$Ii), op: Ii"
            in str(context.exception)
        )
