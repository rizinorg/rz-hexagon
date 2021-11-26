#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

# This script parses the system instructions in the prgrammers references manual.
# It ignores most of fancy instruction properties like .new operands, 32bit immediates, HVX instructions
# etc. Simply because it gets too complex and the system isntructions don't use those properties.

import json
import re


def parse_ops(ops: list):
    ret = list()
    for op in ops:
        op_type = ""
        if re.search(r"R[a-z]{2}", op["op"]):
            op_type = "DoubleRegs"
        elif re.search(r"R[a-z]", op["op"]):
            op_type = "IntRegs"
        elif re.search(r"S[a-z]{2}", op["op"]):
            op_type = "SysRegs64"
        elif re.search(r"S[a-z]", op["op"]):
            op_type = "SysRegs"
        elif re.search(r"P[a-z]", op["op"]):
            op_type = "PredRegs"
        elif re.search(r"I[Ii]", op["op"]):
            op_type = op["sign"].lower() + op["bits"] + "_" + op["shift"] + "Imm"
        else:
            print("Operand " + op + " not yet implemented.")

        ret.append([{"def": op_type, "kind": "def", "printable": op_type}, op["op"]])
        op.update({"type": op_type})
    return ret, ops


def manual_syntax_to_llvm_syntax(syntax: str) -> dict:
    llvm_syntax = syntax
    ret = {"in_ops": [], "out_ops": [], "llvm_syntax": ""}
    in_ops = list()
    out_ops = list()

    # Retrieve registers
    for reg in re.findall(r"([RSGVP][dstx]{1,2})", syntax):
        if reg[0] == "P":
            llvm_reg = "$" + reg + "4"
        else:
            llvm_reg = "$" + reg + "32"
        llvm_syntax = re.sub(reg, llvm_reg, llvm_syntax)
        if reg[1] == "d":
            out_ops.append({"op": llvm_reg.strip("$"), "char": reg[1], "enc_i": 0})
        elif reg[1] == "x":
            out_ops.append({"op": llvm_reg.strip("$"), "char": reg[1], "enc_i": 0})
            in_ops.append({"op": llvm_reg.strip("$") + "in", "char": reg[1]})
        else:
            in_ops.append({"op": llvm_reg.strip("$"), "char": reg[1], "enc_i": 0})

    # Replace immediate. E.g: #u11:3 with #$Ii.
    for tup in re.findall(r"(#[uUsS]\d{1,2})(:\d)?", llvm_syntax):
        imm = tup[0] if len(tup) == 1 else "".join(tup)
        if imm[1] == "u" or imm[1] == "s":
            llvm_imm = "#$Ii"
            llvm_syntax = re.sub(imm, llvm_imm, llvm_syntax)
        elif imm[1] == "U" or imm[1] == "S":
            llvm_imm = "#$II"
            llvm_syntax = re.sub(imm, llvm_imm, llvm_syntax)
        else:
            print("Unkown immediate: " + str(imm))
        in_ops.append(
            {
                "op": llvm_imm.strip("#").strip("$"),
                "char": llvm_imm[3],
                "enc_i": 0,
                "sign": imm[1],
                "bits": tup[0][1:],
                "shift": 0 if len(tup) == 1 else tup[1][1:],
            }
        )
    llvm_syntax = re.sub(r"=", " = ", llvm_syntax)

    ret["llvm_syntax"] = llvm_syntax
    ret["llvm_in_ops"], ret["in_ops"] = parse_ops(in_ops)
    ret["llvm_out_ops"], ret["out_ops"] = parse_ops(out_ops)
    return ret


def syntax_to_enum_name(syntax: str) -> str:
    return ("IMPORTED_" + re.sub(r"[()=$#,+:]", "_", syntax)).strip("_")


def main():
    with open("Instruction-template.json") as f:
        instr_temp = json.load(f)

    with open("Hexagon-Prog-Manual-v67-Ch-SYSTEM.txt") as f:
        for line in f:
            # Search for encoding pattern of bits. E.g.:
            #  1  0  1  0 0  0   0  0  1   0  1   s  s  s  s  s  P   P -  t   t  t t  t  - - -  - - - d   d memw_locked(Rs,Pd)=Rt
            res = re.search(r"^\s*(([10sPd\-xti]\s+){32})(.+$)", line)
            if res:
                enc = res.group(1).replace(" ", "")
                syntax = res.group(3)
                name = syntax_to_enum_name(syntax)
                llvm_bundle = manual_syntax_to_llvm_syntax(syntax)
                instr = dict()
                instr[name] = instr_temp
                instr[name]["!name"] = name
                instr[name]["AsmString"] = llvm_bundle["llvm_syntax"]
                instr[name]["InOperandList"]["args"] = llvm_bundle["llvm_in_ops"]
                instr[name]["OutOperandList"]["args"] = llvm_bundle["llvm_out_ops"]
                instr[name]["Constraints"] = ""
                if "$Rx32in" in [r[1] for r in instr[name]["InOperandList"]["args"]]:
                    instr[name]["Constraints"] = "$Rx32 = $Rx32in"
                elif "$Rxx32in" in [r[1] for r in instr[name]["InOperandList"]["args"]]:
                    instr[name]["Constraints"] = "$Rxx32 = $Rxx32in"
                instr[name]["Inst"] = list()
                for bit in enc:
                    if bit == "1" or bit == "0":
                        instr[name]["Inst"].insert(0, int(bit))
                    elif bit == "-":
                        instr[name]["Inst"].insert(0, 0)
                    elif bit == "P":
                        instr[name]["Inst"].insert(0, None)
                    else:
                        for op in llvm_bundle["in_ops"] + llvm_bundle["out_ops"]:
                            if bit == op["char"] and op["op"][-2:] != "in":
                                bit_index = (
                                    enc.count(op["char"]) - int(op["enc_i"])
                                ) - 1
                                instr[name]["Inst"].insert(
                                    0, {"index": bit_index, "var": op["op"]}
                                )
                                op["enc_i"] += 1
                                break
                with open("./instructions/" + name + ".json", "w+") as g:
                    g.write(json.dumps(instr, indent=2))


if __name__ == "__main__":
    main()
