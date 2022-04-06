# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

from bitarray import bitarray
import unittest

import PluginInfo
from DuplexInstruction import DuplexInstruction
from LLVMImporter import LLVMImporter
from InstructionEncoding import InstructionEncoding
from Operand import SparseMask
from SubInstruction import SubInstruction


class TestInstructionEncoding(unittest.TestCase):
    def setUp(self) -> None:
        self.interface = LLVMImporter(False, test_mode=True)
        self.json = self.interface.hexArch

    def test_manual_mask(self) -> None:
        self.assertEqual(
            "011111000IIIIIIIPPIiiiiiiiiddddd",
            InstructionEncoding(self.json["A2_combineii"]["Inst"]).docs_mask,
        )
        self.assertEqual(
            "11110101000sssssPP0ttttt000ddddd",
            InstructionEncoding(self.json["A2_combinew"]["Inst"]).docs_mask,
        )
        self.assertEqual(
            "1011iiiiiiisssssPPiiiiiiiiiddddd",
            InstructionEncoding(self.json["A2_addi"]["Inst"]).docs_mask,
        )
        self.assertEqual(
            "0000iiiiiiiiiiiiPPiiiiiiiiiiiiii",
            InstructionEncoding(self.json["A4_ext"]["Inst"]).docs_mask,
        )

    def test_bit_masks(self) -> None:
        # Initializing a bitarray with a string, it interprets the bit most to the right as the MSB.
        # In the manual the MSB is the left most.
        # Therefore we reverse the string here.
        self.assertEqual(
            bitarray("00000000000000000000000000011111"[::-1], endian="little"),
            InstructionEncoding(self.json["A2_combineii"]["Inst"]).operand_masks["Rdd32"],
        )
        self.assertEqual(
            bitarray("00000000000000000001111111100000"[::-1], endian="little"),
            InstructionEncoding(self.json["A2_combineii"]["Inst"]).operand_masks["Ii"],
        )
        self.assertEqual(
            bitarray("00000000011111110010000000000000"[::-1], endian="little"),
            InstructionEncoding(self.json["A2_combineii"]["Inst"]).operand_masks["II"],
        )

        self.assertEqual(
            bitarray("00000000000000000001111100000000"[::-1], endian="little"),
            InstructionEncoding(self.json["A2_combinew"]["Inst"]).operand_masks["Rt32"],
        )
        self.assertEqual(
            bitarray("00000000000111110000000000000000"[::-1], endian="little"),
            InstructionEncoding(self.json["A2_combinew"]["Inst"]).operand_masks["Rs32"],
        )
        self.assertEqual(
            bitarray("00001111111111110011111111111111"[::-1], endian="little"),
            InstructionEncoding(self.json["A4_ext"]["Inst"]).operand_masks["Ii"],
        )

    def test_get_i_class(self) -> None:
        self.assertEqual(
            0xD,
            InstructionEncoding(self.json["A2_addh_h16_hh"]["Inst"]).get_i_class(),
        )

        high = SubInstruction(self.json["SL2_return_tnew"])
        low = SubInstruction(self.json["SS2_storewi1"])
        d = DuplexInstruction.get_duplex_i_class_of_instr_pair(low=low, high=high)

        duplex = DuplexInstruction(self.json[d.name], low=low, high=high)

        self.assertEqual(0xD, duplex.encoding.get_i_class())

    def test_num_representation(self) -> None:
        self.assertEqual(
            0b1111101000110,
            InstructionEncoding(self.json["SL2_return_tnew"]["Inst"]).num_representation,
        )

    def test_correct_operand_names(self) -> None:
        # TODO
        pass

    # RIZIN SPECIFIC
    def test_shifting_c_code(self) -> None:
        self.assertEqual(
            "{ 0x8, 5 }",
            SparseMask(InstructionEncoding(self.json["A2_combineii"]["Inst"]).operand_masks["Ii"]).c_template,
        )
        self.assertEqual(
            "{ 0x1, 13 }, { 0x7, 16 }",
            SparseMask(InstructionEncoding(self.json["A2_combineii"]["Inst"]).operand_masks["II"]).c_template,
        )

        self.assertEqual(
            "{ 0xe, 0 }, { 0xc, 16 }",
            SparseMask(InstructionEncoding(self.json["A4_ext"]["Inst"]).operand_masks["Ii"]).c_template,
        )
