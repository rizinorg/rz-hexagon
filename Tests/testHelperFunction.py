# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import unittest

from bitarray import bitarray

from helperFunctions import bitarray_to_uint, list_to_bitarray, list_to_int


class TestHelperFunction(unittest.TestCase):
    def test_list_to_bitarray(self):
        array = list_to_bitarray([0, 0, 1], endian="little")
        self.assertEqual(bitarray("001", endian="little"), array)

        array = list_to_bitarray([0, 0, 1], endian="big")
        self.assertEqual(bitarray("001", endian="big"), array)

        array = list_to_bitarray([1, 0, 0], endian="little")
        self.assertEqual(bitarray("100", endian="little"), array)

        array = list_to_bitarray([1, 0, 0], endian="big")
        self.assertEqual(bitarray("100", endian="big"), array)

    def test_bitarray_to_int(self):
        n = bitarray_to_uint(bitarray("001"), endian="little")
        self.assertEqual(4, n)

        n = bitarray_to_uint(bitarray("001"), endian="big")
        self.assertEqual(1, n)

        n = bitarray_to_uint(bitarray("010"), endian="little")
        self.assertEqual(2, n)

        n = bitarray_to_uint(bitarray("010"), endian="big")
        self.assertEqual(2, n)

        n = bitarray_to_uint(bitarray("011"), endian="little")
        self.assertEqual(6, n)

        n = bitarray_to_uint(bitarray("011"), endian="big")
        self.assertEqual(3, n)

    def test_list_to_int(self):
        n = list_to_int([0, 0, 1], endian="little")
        self.assertEqual(4, n)

        n = list_to_int([0, 0, 1], endian="big")
        self.assertEqual(1, n)

        n = list_to_int([0, 1, 0], endian="little")
        self.assertEqual(2, n)

        n = list_to_int([0, 1, 0], endian="big")
        self.assertEqual(2, n)

        n = list_to_int([0, 1, 1], endian="little")
        self.assertEqual(6, n)

        n = list_to_int([0, 1, 1], endian="big")
        self.assertEqual(3, n)
