# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

from enum import StrEnum

from ImplementationException import ImplementationException
from Instruction import Instruction
from UnexpectedException import UnexpectedException


class SubInstrNamespace(StrEnum):
    A = "SUBINSN_A"
    L1 = "SUBINSN_L1"
    L2 = "SUBINSN_L2"
    S1 = "SUBINSN_S1"
    S2 = "SUBINSN_S2"


class SubInstruction(Instruction):
    def __init__(self, llvm_instruction: dict):
        if llvm_instruction["Type"]["def"] != "TypeSUBINSN":
            raise UnexpectedException(
                "Can not initialize a sub instruction with a normal"
                " instruction object:" + "{}".format(llvm_instruction["!name"])
            )
        super(SubInstruction, self).__init__(llvm_instruction)

        namespace = llvm_instruction["DecoderNamespace"]
        try:
            self.namespace = SubInstrNamespace(namespace)
        except KeyError:
            raise ImplementationException("Sub instruction namespace: {} is not in Enum".format(namespace))
        self.is_sub_instruction = True
        self.enc_number_representation = None
