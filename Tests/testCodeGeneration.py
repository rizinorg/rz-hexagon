# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import unittest

from LLVMImporter import LLVMImporter


class TestInstruction(unittest.TestCase):
    def setUp(self):
        self.interface = LLVMImporter(False, test_mode=True)
        self.json = self.interface.hexArch

    def test_code_generation(self) -> None:
        pass
