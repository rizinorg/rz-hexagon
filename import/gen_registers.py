#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import json

regs = [
    "sgp0",  # s0
    "sgp1",  # s1
    "stid",  # s2
    "elr",  # s3
    "badva0",  # s4
    "badva1",  # s5
    "ssr",  # s6
    "ccr",  # s7
    "htid",  # s8
    "badva",  # s9
    "imask",  # s10
    "gevb",  # s11
    "s12",  # s12
    "s13",  # s13
    "s14",  # s14
    "s15",  # s15
    "evb",  # s16
    "modectl",  # s17
    "syscfg",  # s18
    "s19",  # s19
    "ipendad",  # s20
    "vid",  # s21
    "vid1",  # s22
    "bestwait",  # s23
    "s24",  # s24
    "schedcfg",  # s25
    "s26",  # s26
    "cfgbase",  # s27
    "diag",  # s28
    "rev",  # s29
    "pcyclelo",  # s30
    "pcyclehi",  # s31
    "isdbst",  # s32
    "isdbcfg0",  # s33
    "isdbcfg1",  # s34
    "livelock",  # s35
    "brkptpc0",  # s36
    "brkptcfg0",  # s37
    "brkptpc1",  # s38
    "brkptcfg1",  # s39
    "isdbmbxin",  # s40
    "isdbmbxout",  # s41
    "isdben",  # s42
    "isdbgpr",  # s43
    "pmucnt4",  # s44
    "pmucnt5",  # s45
    "pmucnt6",  # s46
    "pmucnt7",  # s47
    "pmucnt0",  # s48
    "pmucnt1",  # s49
    "pmucnt2",  # s50
    "pmucnt3",  # s51
    "pmuevtcfg",  # s52
    "s53",  # s53
    "pmuevtcfg1",  # s54
    "pmustid1",  # s55
    "timerlo",  # s56
    "timerhi",  # s57
    "s58",  # s58
    "s59",  # s59
    "s60",  # s60
    "s61",  # s61
    "s62",  # s62
    "s63",  # s63
    "commit1t",  # s64
    "commit2t",  # s65
    "commit3t",  # s66
    "commit4t",  # s67
    "commit5t",  # s68
    "commit6t",  # s69
    "pcycle1t",  # s70
    "pcycle2t",  # s71
    "pcycle3t",  # s72
    "pcycle4t",  # s73
    "pcycle5t",  # s74
    "pcycle6t",  # s75
    "stfinst",  # s76
    "isdbcmd",  # s77
    "isdbver",  # s78
    "brkptinfo",  # s79
    "rgdr3",  # s80
]

with open("Register-template.json") as f:
    reg_temp = json.load(f)
with open("Register64-template.json") as f:
    reg64_temp = json.load(f)
with open("SysRegs-template.json") as f:
    sysregs = json.load(f)
with open("SysRegs64-template.json") as f:
    sysregs64 = json.load(f)

sysregs["SysRegs"]["MemberList"]["args"] = list()
sysregs["SysRegs"]["MemberList"]["printable"] = "(add "
sysregs64["SysRegs64"]["MemberList"]["args"] = list()
sysregs64["SysRegs64"]["MemberList"]["printable"] = "(add "

for i in range(81):
    number_name = "S" + str(i)
    name = regs[i].upper()
    sysregs["SysRegs"]["MemberList"]["args"].append([{"def": name, "kind": "def", "printable": name}])
    sysregs["SysRegs"]["MemberList"]["printable"] += name + ", "

    reg = dict()
    reg[name] = reg_temp

    reg[name]["!name"] = name
    reg[name]["AsmName"] = name.lower()
    if name != number_name:
        reg[name]["AltNames"] = [number_name.lower()]
    reg[name]["HWEncoding"] = list()
    x = i
    for _ in range(16):
        reg[name]["HWEncoding"].append(x % 2)
        x = x >> 1
    with open("registers/{}.json".format(name.upper()), "w") as f:
        f.write(json.dumps(reg, indent=2))

    # Gen double reg
    if i % 2 == 1:
        reg = dict()
        number_name = "S{}_{}".format(i, i - 1)
        name = number_name
        sysregs64["SysRegs64"]["MemberList"]["args"].append([{"def": name, "kind": "def", "printable": name}])
        sysregs64["SysRegs64"]["MemberList"]["printable"] += name + ", "

        reg[name] = reg_temp

        reg[name]["!name"] = name
        reg[name]["AsmName"] = "s{}:{}".format(i, i - 1)
        reg[name]["HWEncoding"] = list()
        x = i - 1
        for _ in range(16):
            reg[name]["HWEncoding"].append(x % 2)
            x = x >> 1
        with open("registers/{}.json".format(name.upper()), "w") as f:
            f.write(json.dumps(reg, indent=2))

sysregs["SysRegs"]["MemberList"]["printable"] = sysregs["SysRegs"]["MemberList"]["printable"][:-2] + ")"
sysregs64["SysRegs64"]["MemberList"]["printable"] = sysregs64["SysRegs64"]["MemberList"]["printable"][:-2] + ")"
with open("registers/SysRegs.json".format(name.upper()), "w") as f:
    f.write(json.dumps(sysregs, indent=2))
with open("registers/SysRegs64.json".format(name.upper()), "w") as f:
    f.write(json.dumps(sysregs64, indent=2))
