# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import unittest

from DuplexInstruction import DuplexInstruction
from Immediate import Immediate
from LLVMImporter import LLVMImporter
from Register import Register
from SubInstruction import SubInstruction


class TestDuplex(unittest.TestCase):
    def setUp(self) -> None:
        self.interface = LLVMImporter(False, test_mode=True)
        self.json = self.interface.hexArch

    def test_encoding(self) -> None:
        # Name: DUPLEX_HIGH_SL2_RETURN_TNEW_LOW_SS2_STOREWI1
        high = SubInstruction(self.json["SL2_return_tnew"])
        low = SubInstruction(self.json["SS2_storewi1"])
        d = DuplexInstruction.get_duplex_i_class_of_instr_pair(low=low, high=high)

        duplex = DuplexInstruction(self.json[d.name], low=low, high=high)
        self.assertEqual("1101111101000110EE110001ssssiiii", duplex.encoding.docs_mask)
        self.assertEqual("if (p0.new) dealloc_return:nt ; memw(Rs+Ii) = #1", duplex.syntax)
        self.assertTrue(duplex.encoding.duplex_encoding)

        # DUPLEX_HIGH_SA1_SETI_LOW_SL1_LOADRUB_IO
        high = SubInstruction(self.json["SA1_seti"])
        low = SubInstruction(self.json["SL1_loadrub_io"])
        d = DuplexInstruction.get_duplex_i_class_of_instr_pair(low=low, high=high)

        duplex = DuplexInstruction(self.json[d.name], low=low, high=high)
        self.assertEqual("010010IIIIIIDDDDEE01iiiissssdddd", duplex.encoding.docs_mask)
        self.assertEqual("RD = II ; Rd = memub(Rs+Ii)", duplex.syntax)
        self.assertTrue(duplex.encoding.duplex_encoding)

        # DUPLEX_HIGH_SA1_COMBINERZ_LOW_SA1_DEC
        # $Rdd8 = combine($Rs16,#0) ; $Rd16 = add($Rs16,#$n1)
        high = SubInstruction(self.json["SA1_combinezr"])
        low = SubInstruction(self.json["SA1_dec"])
        d = DuplexInstruction.get_duplex_i_class_of_instr_pair(low=low, high=high)

        duplex = DuplexInstruction(self.json[d.name], low=low, high=high)
        self.assertEqual("RDD = combine(#0,RS) ; Rd = add(Rs,n1)", duplex.syntax)
        self.assertEqual("00111101SSSS0DDDEE110011ssssdddd", duplex.encoding.docs_mask)
        self.assertTrue(duplex.encoding.duplex_encoding)

    def test_parse_instruction(self) -> None:
        # TODO
        #  - actual vs. theoretical new operands, also predicates
        #  - Actual vs. theoretical indices
        #  - Operand attributes (new, extendable)
        #  - Op-type and scale values etc
        #  - Names
        #  - Rx and Rxin register

        # self.test_SA1_cmpeqi_SS1_storeb_io()
        # self.test_SA1_setin1_SA1_addrx()
        pass

    def test_SA1_cmpeqi_SS1_storeb_io(self) -> None:
        # p0 = cmp.eq($RS16,#$II) ; memb($Rs16+#$Ii) = $Rt16
        high = SubInstruction(self.json["SA1_cmpeqi"])
        low = SubInstruction(self.json["SS1_storeb_io"])
        d = DuplexInstruction.get_duplex_i_class_of_instr_pair(low=low, high=high)
        duplex = DuplexInstruction(self.json[d.name], low=low, high=high)
        # Assert high instr. operands
        op: Register = duplex.operands["RS16"]
        self.assertTrue(op.is_in_operand)
        self.assertTrue(op.is_general)
        self.assertTrue(op.sub_instr_encoding)
        self.assertFalse(op.is_lower8)
        self.assertFalse(op.is_new_value)
        self.assertEqual(0, op.syntax_index)
        op: Immediate = duplex.operands["II"]
        self.assertTrue(op.is_in_operand)
        self.assertFalse(op.is_extendable)
        self.assertFalse(op.is_signed)
        self.assertFalse(op.is_pc_relative)
        self.assertFalse(op.is_constant)
        self.assertEqual(2, op.encoding_width)
        self.assertEqual(0, op.scale)
        self.assertEqual(2, op.total_width)
        self.assertEqual(1, op.syntax_index)
        # Assert low instr. operands
        op: Register = duplex.operands["Rs16"]
        self.assertTrue(op.is_in_operand)
        self.assertTrue(op.is_general)
        self.assertTrue(op.sub_instr_encoding)
        self.assertFalse(op.is_lower8)
        self.assertFalse(op.is_new_value)
        self.assertEqual(2, op.syntax_index)
        op: Immediate = duplex.operands["Ii"]
        self.assertTrue(op.is_in_operand)
        self.assertFalse(op.is_extendable)
        self.assertFalse(op.is_signed)
        self.assertFalse(op.is_pc_relative)
        self.assertFalse(op.is_constant)
        self.assertEqual(4, op.encoding_width)
        self.assertEqual(0, op.scale)
        self.assertEqual(4, op.total_width)
        self.assertEqual(3, op.syntax_index)
        op: Register = duplex.operands["Rt16"]
        self.assertTrue(op.is_in_operand)
        self.assertTrue(op.sub_instr_encoding)
        self.assertTrue(op.is_general)
        self.assertFalse(op.is_lower8)
        self.assertFalse(op.is_new_value)
        self.assertEqual(4, op.syntax_index)

    def test_SA1_setin1_SA1_addrx(self) -> None:
        # $Rd16 = #$n1 ; $Rx16 = add($Rx16in,$Rs16)
        high = SubInstruction(self.json["SA1_setin1"])
        low = SubInstruction(self.json["SA1_addrx"])
        d = DuplexInstruction.get_duplex_i_class_of_instr_pair(low=low, high=high)
        duplex = DuplexInstruction(self.json[d.name], low=low, high=high)
        # Assert high instr. operands
        op: Register = duplex.operands["Rd16"]
        self.assertTrue(op.is_out_operand)
        self.assertTrue(op.is_general)
        self.assertTrue(op.sub_instr_encoding)
        self.assertFalse(op.is_lower8)
        self.assertFalse(op.is_new_value)
        self.assertEqual(0, op.syntax_index)
        op: Immediate = duplex.operands["n1"]
        self.assertTrue(op.is_in_operand)
        self.assertTrue(op.is_constant)
        self.assertFalse(op.is_extendable)
        self.assertTrue(op.is_signed)
        self.assertFalse(op.is_pc_relative)
        self.assertEqual(1, op.syntax_index)
        # Assert low instr. operands
        op: Register = duplex.operands["Rx16"]
        self.assertTrue(op.is_out_operand)
        self.assertTrue(op.is_general)
        self.assertTrue(op.sub_instr_encoding)
        self.assertFalse(op.is_lower8)
        self.assertFalse(op.is_new_value)
        self.assertEqual(2, op.syntax_index)
        op: Register = duplex.operands["Rx16in"]
        self.assertTrue(op.is_in_operand)
        self.assertTrue(op.is_general)
        self.assertTrue(op.sub_instr_encoding)
        self.assertFalse(op.is_lower8)
        self.assertFalse(op.is_new_value)
        self.assertEqual(3, op.syntax_index)
        op: Register = duplex.operands["Rs16"]
        self.assertTrue(op.is_in_operand)
        self.assertTrue(op.sub_instr_encoding)
        self.assertTrue(op.is_general)
        self.assertFalse(op.is_lower8)
        self.assertFalse(op.is_new_value)
        self.assertEqual(4, op.syntax_index)

    def test_SA1_addi_SL1_loadri_io(self) -> None:
        # $Rx16 = add($Rx16in,#$II) ; $Rd16 = memw($Rs16+#$Ii)
        high = SubInstruction(self.json["SA1_addi"])
        low = SubInstruction(self.json["SL1_loadri_io"])
        d = DuplexInstruction.get_duplex_i_class_of_instr_pair(low=low, high=high)
        duplex = DuplexInstruction(self.json[d.name], low=low, high=high)

        # High instruction
        op: Register = duplex.operands["Rx16"]
        self.assertTrue(op.is_out_operand)
        self.assertTrue(op.is_general)
        self.assertTrue(op.sub_instr_encoding)
        self.assertFalse(op.is_lower8)
        self.assertFalse(op.is_new_value)
        self.assertEqual(0, op.syntax_index)
        op: Register = duplex.operands["Rx16in"]
        self.assertTrue(op.is_in_operand)
        self.assertTrue(op.is_general)
        self.assertTrue(op.sub_instr_encoding)
        self.assertFalse(op.is_lower8)
        self.assertFalse(op.is_new_value)
        self.assertEqual(1, op.syntax_index)
        op: Immediate = duplex.operands["II"]
        self.assertTrue(op.is_in_operand)
        self.assertTrue(op.is_extendable)
        self.assertTrue(op.is_signed)
        self.assertFalse(op.is_pc_relative)
        self.assertFalse(op.is_constant)
        self.assertEqual(32, op.encoding_width)
        self.assertEqual(0, op.scale)
        self.assertEqual(32, op.total_width)
        self.assertEqual(2, op.syntax_index)

        # Assert low instr. operands
        op: Register = duplex.operands["Rd16"]
        self.assertTrue(op.is_out_operand)
        self.assertTrue(op.is_general)
        self.assertTrue(op.sub_instr_encoding)
        self.assertFalse(op.is_lower8)
        self.assertFalse(op.is_new_value)
        self.assertEqual(3, op.syntax_index)
        op: Register = duplex.operands["Rs16"]
        self.assertTrue(op.is_in_operand)
        self.assertTrue(op.sub_instr_encoding)
        self.assertTrue(op.is_general)
        self.assertFalse(op.is_lower8)
        self.assertFalse(op.is_new_value)
        self.assertEqual(4, op.syntax_index)
        op: Immediate = duplex.operands["Ii"]
        self.assertTrue(op.is_in_operand)
        self.assertFalse(op.is_extendable)
        self.assertFalse(op.is_signed)
        self.assertFalse(op.is_pc_relative)
        self.assertFalse(op.is_constant)
        self.assertEqual(4, op.encoding_width)
        self.assertEqual(2, op.scale)
        self.assertEqual(6, op.total_width)
        self.assertEqual(5, op.syntax_index)
