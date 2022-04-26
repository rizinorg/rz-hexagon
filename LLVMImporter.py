#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import itertools
import json
import os
import re
import subprocess
import argparse

from HardwareRegister import HardwareRegister
from DuplexInstruction import DuplexInstruction, DuplexIClass
from ImplementationException import ImplementationException
from Instruction import Instruction
from SubInstruction import SubInstruction
from helperFunctions import (
    log,
    LogLevel,
    get_generation_warning_c_code,
    unfold_llvm_sequence,
    get_include_guard,
    make_c_block,
    set_pos_after_license,
    get_license,
    get_generation_timestamp,
    compare_src_to_old_src,
    include_file,
)
import PluginInfo
import HexagonArchInfo
from InstructionTemplate import PARSE_BITS_MASK_CONST


class LLVMImporter:
    config = dict()
    hexArch = dict()
    hexagon_target_json_path = ""
    llvm_instructions = dict()
    normal_instruction_names = list()
    normal_instructions = dict()
    sub_instruction_names = list()
    sub_instructions = dict()
    duplex_instructions_names = list()
    duplex_instructions = dict()
    hardware_regs = dict()

    def __init__(self, build_json: bool, test_mode=False):
        self.test_mode = test_mode
        if self.test_mode:
            self.hexagon_target_json_path = "../Hexagon.json"
        else:
            self.hexagon_target_json_path = "Hexagon.json"
        self.get_import_config()
        if build_json:
            self.generate_hexagon_json()
        else:
            if not os.path.exists(self.hexagon_target_json_path):
                log("No Hexagon.json found. Please check out the help message to generate it.", LogLevel.ERROR)
                exit()
            self.set_llvm_commit_info(use_prev=True)

        with open(self.hexagon_target_json_path) as file:
            self.hexArch = json.load(file)
        self.update_hex_arch()
        log("LLVM Hexagon target dump successfully loaded.")

        # Save types
        HexagonArchInfo.IMMEDIATE_TYPES = self.hexArch["!instanceof"]["Operand"]
        HexagonArchInfo.REG_CLASS_NAMES = self.hexArch["!instanceof"]["RegisterClass"]
        HexagonArchInfo.LLVM_FAKE_REGS = self.hexArch["!instanceof"]["HexagonFakeReg"]
        HexagonArchInfo.ALL_REG_NAMES = self.hexArch["!instanceof"]["DwarfRegNum"]
        HexagonArchInfo.CALLEE_SAVED_REGS = [name[0]["def"] for name in self.hexArch["HexagonCSR"]["SaveList"]["args"]]
        HexagonArchInfo.CC_REGS = self.get_cc_regs()

        self.unchanged_files = []  # Src files which had no changes after generation.

        # RIZIN SPECIFIC
        # Name of the function which parses the encoded register index bits.
        self.reg_resolve_decl = list()

        self.parse_hardware_registers()
        self.parse_instructions()
        self.generate_duplex_instructions()
        self.check_insn_syntax_length()
        if not test_mode:
            self.generate_rizin_code()
            self.generate_decompiler_code()
            self.add_license_info_header()
            self.apply_clang_format()
        log("Done")

    def get_import_config(self):
        """Loads the importer configuration from a file and writes it to self.config"""
        cwd = os.getcwd()
        log("Load LLVMImporter configuration from {}/.config".format(cwd))
        if cwd.split("/")[-1] == "rz-hexagon" or self.test_mode:
            self.config["GENERATOR_ROOT_DIR"] = cwd if not self.test_mode else "/".join(cwd.split("/")[:-1])
            if not os.path.exists(".config"):
                with open(cwd + "/.config", "w") as f:
                    config = "# Configuration for th LLVMImporter.\n"
                    config += "LLVM_PROJECT_REPO_DIR = /path/to/llvm_project"
                    f.write(config)
                log(
                    "This is your first time running the generator{}.".format(" TESTS" if self.test_mode else "")
                    + " Please set the path to the llvm_project repo in {}/.config.".format(cwd)
                )
                exit()
            with open(cwd + "/.config") as f:
                for line in f.readlines():
                    ln = line.strip()
                    if ln[0] == "#":
                        continue
                    ln = ln.split("=")
                    if ln[0].strip() == "LLVM_PROJECT_REPO_DIR":
                        dr = ln[1].strip()
                        if not os.path.exists(dr):
                            log(
                                "The LLVM_PROJECT_REPO_DIR is set to an invalid directory: '{}'".format(dr),
                                LogLevel.ERROR,
                            )
                            exit()
                        self.config["LLVM_PROJECT_REPO_DIR"] = dr
                        self.config["LLVM_PROJECT_HEXAGON_DIR"] = dr + "/llvm/lib/Target/Hexagon"
                    else:
                        log("Unknown configuration in config file: '{}'".format(ln[0]), LogLevel.WARNING)
        else:
            log("Please execute this script in the rz-hexagon directory.", LogLevel.ERROR)
            exit()

    def set_llvm_commit_info(self, use_prev: bool):
        """Writes the LLVM commit hash and commit date to self.config.

        :param use_prev: If True it uses the information when Hexagon.json was generated previously.
            False: it gets the date of the current checked out LLVM commit.
        """

        if not use_prev:
            self.config["LLVM_COMMIT_DATE"] = (
                subprocess.check_output(
                    ["git", "show", "-s", "--format=%ci", "HEAD"], cwd=self.config["LLVM_PROJECT_REPO_DIR"]
                )
                .decode("ascii")
                .strip("\n")
            )
            self.config["LLVM_COMMIT_DATE"] += " (ISO 8601 format)"
            self.config["LLVM_COMMIT_HASH"] = (
                subprocess.check_output(
                    ["git", "show", "-s", "--format=%H", "HEAD"], cwd=self.config["LLVM_PROJECT_REPO_DIR"]
                )
                .decode("ascii")
                .strip("\n")
            )
            with open(".last_llvm_commit_info", "w") as f:
                f.write(self.config["LLVM_COMMIT_DATE"])
                f.write("\n")
                f.write(self.config["LLVM_COMMIT_HASH"])
        else:
            if os.path.exists(".last_llvm_commit_info"):
                with open(".last_llvm_commit_info", "r") as f:
                    self.config["LLVM_COMMIT_DATE"] = str(f.readline()).strip()
                    self.config["LLVM_COMMIT_HASH"] = str(f.readline()).strip()
            else:
                log("No previous LLVM commit info found.", LogLevel.VERBOSE if self.test_mode else LogLevel.WARNING)
                self.config["LLVM_COMMIT_DATE"] = "Test" if self.test_mode else "None"
                self.config["LLVM_COMMIT_HASH"] = "Test" if self.test_mode else "None"

    def generate_hexagon_json(self):
        """Generates the Hexagon.json file with LLVMs tablegen."""

        log("Generate Hexagon.json from LLVM target descriptions.")
        self.set_llvm_commit_info(use_prev=False)
        subprocess.call(
            [
                "llvm-tblgen",
                "-I",
                "../../../include/",
                "--dump-json",
                "-o",
                "{}/Hexagon.json".format(self.config["GENERATOR_ROOT_DIR"]),
                "Hexagon.td",
            ],
            cwd=self.config["LLVM_PROJECT_HEXAGON_DIR"],
        )

    def update_hex_arch(self):
        """Imports system instructions and registers described in the manual but not implemented by LLVM."""
        reg_count = 0
        self.hexArch["!instanceof"]["RegisterClass"] += [
            "SysRegs",
            "SysRegs64",
        ]
        reg_dir = "./import/registers/" if not self.test_mode else "../import/registers/"
        for filename in sorted(os.listdir(reg_dir)):
            if filename.split(".")[-1] != "json":
                continue
            with open(reg_dir + filename) as f:
                reg = json.load(f)
            reg_name = list(reg.keys())[0]
            if reg_name != "SysRegs" or reg_name != "SysRegs64":
                if reg_name in self.hexArch["!instanceof"]["DwarfRegNum"]:
                    raise ImplementationException(
                        "Register {} already present in the LLVM definitions."
                        " Please check whether LLVM implements System/Monitor"
                        " instructions and system registers etc.".format(reg_name)
                    )
                self.hexArch["!instanceof"]["DwarfRegNum"] += reg.keys()
                reg_count += 1
            self.hexArch.update(reg)

        instr_count = 0
        insn_dir = "./import/instructions/" if not self.test_mode else "../import/instructions/"
        for filename in sorted(os.listdir(insn_dir)):
            if filename.split(".")[-1] != "json":
                continue
            instn_name = filename.replace(".json", "")
            with open(insn_dir + filename) as f:
                insn = json.load(f)
            syntax_list = list()
            for llvm_instr in self.hexArch["!instanceof"]["HInst"]:
                syntax_list.append(self.hexArch[llvm_instr]["AsmString"])
            if "UNDOCUMENTED" not in instn_name and insn[instn_name]["AsmString"] in syntax_list:
                continue
            self.hexArch.update(insn)
            self.hexArch["!instanceof"]["HInst"] += list(insn.keys())
            instr_count += 1
        log("Imported {} registers.".format(reg_count))
        log("Imported {} instructions.".format(instr_count))

    def parse_instructions(self) -> None:
        for i, i_name in enumerate(self.hexArch["!instanceof"]["HInst"]):
            llvm_instruction = self.hexArch[i_name]
            if llvm_instruction is None:
                log(
                    "Could not find instruction with name: {} in json file.".format(i_name),
                    LogLevel.ERROR,
                )
                continue
            if llvm_instruction["isPseudo"]:
                log(
                    "Pseudo instruction passed. Name: {}".format(i_name),
                    LogLevel.VERBOSE,
                )
                continue
            log("{} | Parse {}".format(i, i_name), LogLevel.VERBOSE)
            self.llvm_instructions[i_name] = llvm_instruction

            if llvm_instruction["Type"]["def"] == "TypeSUBINSN":
                self.sub_instruction_names.append(i_name)
                self.sub_instructions[i_name] = SubInstruction(llvm_instruction)
            else:
                self.normal_instruction_names.append(i_name)
                self.normal_instructions[i_name] = Instruction(llvm_instruction)

        log("Parsed {} normal instructions.".format(len(self.normal_instructions)))
        log("Parsed {} sub-instructions.".format(len(self.sub_instructions)))

    def generate_duplex_instructions(self) -> None:
        sub_instr_pairs = itertools.product(self.sub_instructions.values(), self.sub_instructions.values())
        for pair in sub_instr_pairs:
            low_instr = pair[0]
            high_instr = pair[1]
            i_class = DuplexInstruction.get_duplex_i_class_of_instr_pair(low=low_instr, high=high_instr)
            if i_class != DuplexIClass.INVALID and DuplexInstruction.fulfill_constraints(low_instr, high_instr):
                llvm_dup_instr = self.hexArch[i_class.name]
                dup_instr = DuplexInstruction(
                    llvm_duplex_instr=llvm_dup_instr,
                    low=low_instr,
                    high=high_instr,
                )
                self.duplex_instructions[dup_instr.name] = dup_instr
                self.duplex_instructions_names.append(dup_instr.name)
                log("Duplex instruction generated: {}".format(dup_instr.name), LogLevel.DEBUG)
        log("Generated {} duplex instructions.".format(len(self.duplex_instructions)))

    def parse_hardware_registers(self) -> None:
        cc = 0
        cr = 0
        for reg_class_name in HexagonArchInfo.REG_CLASS_NAMES:
            # LLVM fake register class; VectRegRev = reverse double register: V0:1 instead of V1:0
            if reg_class_name == "UsrBits" or reg_class_name == "VectRegRev":
                continue
            # Register class which holds all new register of an arch version. Irrelevant for us at the moment.
            if reg_class_name == "V65Regs" or reg_class_name == "V62Regs":
                continue

            self.hardware_regs[reg_class_name] = dict()
            reg_class: dict = self.hexArch[reg_class_name]
            # Use "Alignment" although a "Size" attribute exists. But Double Regs set that to 0.
            size: int = reg_class["Alignment"] if reg_class["Size"] == 0 else reg_class["Size"]

            reg_names = list()
            for a in reg_class["MemberList"]["args"]:
                arg = a[0]
                if "def" in arg:
                    # VTMP = LLVM fake register
                    if arg["def"] == "VTMP":
                        continue
                    if reg_class_name == "CtrRegs" and arg["def"] == "C8":
                        # For whatever reason this C8 occurs twice, but as USR reg.
                        # We better use the USR reg as it lists c8 als alternative name for itself.
                        continue
                    reg_names.append(arg["def"])
                elif "sequence" in arg["printable"]:
                    reg_names = reg_names + unfold_llvm_sequence(arg["printable"])
                # Remove registers whichs tart with WR; WR register are reverse double vector regs: V0:1 instead of V1:0
                # TODO This is not nice. Isn't there a simpler way?
                reg_names = [name for name in reg_names if not re.search(r"WR\d{1,2}", name)]

            for name in reg_names:
                llvm_reg = self.hexArch[name]
                reg = HardwareRegister(
                    llvm_reg_class=reg_class_name,
                    name=name,
                    llvm_object=llvm_reg,
                    size=size,
                )
                self.hardware_regs[reg_class_name][name] = reg
                cr += 1
                log(
                    "Added reg: {}::{} with hw encoding: {}".format(name, reg_class_name, reg.hw_encoding),
                    LogLevel.DEBUG,
                )

            cc += 1
        log("Parsed {} hardware registers of {} different register classes.".format(cr, cc))

    def check_insn_syntax_length(self):
        for instr_set in [
            self.normal_instructions.values(),
            self.duplex_instructions.values(),
        ]:
            for insn in instr_set:
                if len(insn.syntax) >= 128:
                    sl = len(insn.syntax) + 1  # +1 for \0 in the string
                    raise ImplementationException(
                        "The mnemonic variable is at the moment only 128 byte."
                        + "This syntax takes at least {}+1 bytes.".format(sl)
                    )

    def get_cc_regs(self) -> dict:
        """Returns a list of register names which are argument or return register in the calling convention.
        This part is a bit tricky. The register names are stored in objects named "anonymous_XXX" in Hexagon.json.
        Since they do not have a explicit name, we can only check check the names against the source.

        Note: LLVM defines the calling convention in: HexagonCallingConv.td

        Returns: dict = {"GPR_args":list[str], "GPR_ret":list[str], "HVX_args":list[str], "HVX_ret":list[str],}
        """
        cc_regs = dict()
        anon_obj_names = self.hexArch["!instanceof"]["CCAssignToReg"]
        arg_regs = [reg["def"] for reg in self.hexArch[anon_obj_names[0]]["RegList"]]  # Single
        arg_regs += [reg["def"] for reg in self.hexArch[anon_obj_names[1]]["RegList"]]  # Double
        cc_regs["GPR_args"] = arg_regs

        ret_regs = [reg["def"] for reg in self.hexArch[anon_obj_names[2]]["RegList"]]  # Single
        ret_regs += [reg["def"] for reg in self.hexArch[anon_obj_names[3]]["RegList"]]  # Double
        cc_regs["GPR_ret"] = ret_regs

        hvx_arg_regs = [reg["def"] for reg in self.hexArch[anon_obj_names[4]]["RegList"]]  # Single
        hvx_arg_regs += [reg["def"] for reg in self.hexArch[anon_obj_names[5]]["RegList"]]  # Double
        cc_regs["HVX_args"] = hvx_arg_regs

        hvx_ret_regs = [reg["def"] for reg in self.hexArch[anon_obj_names[6]]["RegList"]]  # Single
        hvx_ret_regs += [reg["def"] for reg in self.hexArch[anon_obj_names[7]]["RegList"]]  # Double
        cc_regs["HVX_ret"] = hvx_ret_regs

        return cc_regs

    # RIZIN SPECIFIC
    def generate_rizin_code(self) -> None:
        log("Generate and write source code.")
        self.build_hexagon_insn_enum_h()
        self.build_hexagon_disas_c()
        self.build_hexagon_c()
        self.build_hexagon_h()
        self.build_asm_hexagon_c()
        self.build_hexagon_arch_c()
        self.build_hexagon_arch_h()
        self.copy_tests()
        self.build_analysis_hexagon_c()
        self.build_cc_hexagon_32_sdb_txt()

        # TODO hexagon.h: Gen - HexOpType, IClasses, Regs and its aliases (system = guest),
        #  + corresponding functions in hexagon.c: hex_get_sub_regpair etc.

    # RIZIN SPECIFIC
    # TODO Wouldn't it be a wonderful world...
    def generate_decompiler_code(self) -> None:
        pass

    # RIZIN SPECIFIC
    def add_license_info_header(self) -> None:
        log("Add license headers")
        for subdir, dirs, files in os.walk("./rizin/"):
            for file in files:
                if file == "hexagon" or file[-3:] == "txt":  # Tests
                    continue
                p = os.path.join(subdir, file)
                if p in self.unchanged_files:
                    continue
                with open(p, "r+") as f:
                    content = f.read()
                    f.seek(0, 0)
                    f.write(get_license() + "\n" + get_generation_timestamp(self.config) + "\n" + content)

    # RIZIN SPECIFIC
    def build_hexagon_insn_enum_h(self, path: str = "./rizin/librz/asm/arch/hexagon/hexagon_insn.h") -> None:
        code = get_generation_warning_c_code()
        code += get_include_guard("hexagon_insn.h")
        code += "enum HEX_INS {"
        enum = ""
        for name in self.normal_instruction_names + self.duplex_instructions_names:
            if "invalid_decode" in name:
                enum = (PluginInfo.INSTR_ENUM_PREFIX + name.upper() + " = 0,") + enum
            else:
                enum += PluginInfo.INSTR_ENUM_PREFIX + name.upper() + ","
        code += enum
        code += "};"
        code += "#endif"

        self.write_src(code, path)

    # RIZIN SPECIFIC
    def build_hexagon_disas_c(self, path: str = "./rizin/librz/asm/arch/hexagon/hexagon_disas.c") -> None:
        code = get_generation_warning_c_code()

        code += include_file("handwritten/hexagon_disas_c/include.c")
        code += include_file("handwritten/hexagon_disas_c/types.c")

        templates_code = "\n\n"

        # Duplexes
        for c in range(0xF):  # Class 0xf is reserved yet.
            templates_code += f"static const HexInsnTemplate templates_duplex_0x{c:x}[] = {{\n"
            for d_instr in self.duplex_instructions.values():
                if d_instr.encoding.get_i_class() == c:
                    templates_code += d_instr.get_template_in_c() + ","
            templates_code += "{ { 0 } }, };\n\n"

        templates_code += "static const HexInsnTemplate *templates_duplex[] = {\n"
        templates_code += ",\n".join([f"templates_duplex_0x{c:x}" for c in range(0xF)])
        templates_code += "};\n\n"

        # Normal instructions
        for c in range(0x10):
            templates_code += f"static const HexInsnTemplate templates_normal_0x{c:x}[] = {{\n"
            for instr in self.normal_instructions.values():
                if instr.encoding.get_i_class() == c:
                    templates_code += instr.get_template_in_c() + ","
            templates_code += "{ { 0 } }, };\n\n"

        templates_code += "static const HexInsnTemplate *templates_normal[] = {\n"
        templates_code += ",\n".join([f"templates_normal_0x{c:x}" for c in range(0x10)])
        templates_code += "};\n\n"

        code += templates_code
        code += include_file("handwritten/hexagon_disas_c/functions.c")

        self.write_src(code, path)

    # RIZIN SPECIFIC
    def build_hexagon_h(self, path: str = "./rizin/librz/asm/arch/hexagon/hexagon.h") -> None:
        indent = PluginInfo.LINE_INDENT
        general_prefix = PluginInfo.GENERAL_ENUM_PREFIX

        code = get_generation_warning_c_code()
        code += "\n"
        code += get_include_guard("hexagon.h")
        code += "\n"

        code += include_file("handwritten/hexagon_h/includes.h")
        code += "\n"

        code += f"#define {PluginInfo.GENERAL_ENUM_PREFIX}MAX_OPERANDS {PluginInfo.MAX_OPERANDS}\n"
        code += f"#define {PluginInfo.GENERAL_ENUM_PREFIX}PARSE_BITS_MASK 0x{PARSE_BITS_MASK_CONST:x}\n\n"
        code += include_file("handwritten/hexagon_h/typedefs.h")
        code += "\n"

        code += "typedef enum {\n"
        code += ",\n".join([HardwareRegister.get_enum_item_of_class(reg_class) for reg_class in self.hardware_regs])
        code += "} HexRegClass;\n\n"

        reg_class: str
        for reg_class in self.hardware_regs:
            code += "typedef enum {\n"

            hw_reg: HardwareRegister
            for hw_reg in sorted(
                self.hardware_regs[reg_class].values(),
                key=lambda x: x.hw_encoding,
            ):
                alias = ",".join(hw_reg.alias)
                code += "{}{} = {},{}".format(
                    indent,
                    hw_reg.enum_name,
                    hw_reg.hw_encoding,
                    " // " + alias + "\n" if alias != "" else "\n",
                )
            code += "}} {}{}; // {}\n\n".format(
                general_prefix,
                HardwareRegister.register_class_name_to_upper(reg_class),
                reg_class,
            )

        code += include_file("handwritten/hexagon_h/macros.h")
        code += "\n"

        if len(self.reg_resolve_decl) == 0:
            raise ImplementationException(
                "Register resolve declarations missing"
                "(They get generated together with hexagon.c)."
                "Please generate hexagon.c before hexagon.h"
            )
        for decl in self.reg_resolve_decl:
            code += decl
        code += "\n"
        code += include_file("handwritten/hexagon_h/declarations.h")
        code += "\n#endif"

        self.write_src(code, path)

    # RIZIN SPECIFIC
    def build_hexagon_c(self, path: str = "./rizin/librz/asm/arch/hexagon/hexagon.c") -> None:
        general_prefix = PluginInfo.GENERAL_ENUM_PREFIX
        code = get_generation_warning_c_code()
        code += include_file("handwritten/hexagon_c/include.c")

        reg_class: str
        for reg_class in self.hardware_regs:
            func_name = HardwareRegister.get_func_name_of_class(reg_class, False)
            function = "\nchar* {}(int opcode_reg, bool get_alias)".format(func_name)
            self.reg_resolve_decl.append(function + ";")
            code += "{} {{".format(function)

            parsing_code = HardwareRegister.get_parse_code_reg_bits(reg_class, "opcode_reg")
            if parsing_code != "":
                code += "{}".format(parsing_code)

            code += "switch (opcode_reg) {"
            code += 'default:return "<err>";'

            hw_reg: HardwareRegister
            for hw_reg in self.hardware_regs[reg_class].values():
                alias = "".join(hw_reg.alias).upper()
                alias_choice = 'get_alias ? "' + alias + '" : "' + hw_reg.asm_name.upper() + '"'
                code += "case {}:\nreturn {};".format(
                    hw_reg.enum_name,
                    alias_choice if alias != "" else '"' + hw_reg.asm_name.upper() + '"',
                )
            code += "}}\n"

        reg_in_cls_decl = (
            f"char *{general_prefix.lower()}" "get_reg_in_class(HexRegClass cls, int opcode_reg, bool get_alias)"
        )
        self.reg_resolve_decl.append(f"{reg_in_cls_decl};")
        code += f"{reg_in_cls_decl} {{\n"
        code += "switch (cls) {\n"
        for reg_class in self.hardware_regs:
            code += f"case {HardwareRegister.get_enum_item_of_class(reg_class)}:\n"
            code += f"return {HardwareRegister.get_func_name_of_class(reg_class, False)}(opcode_reg, get_alias);\n"
        code += "default:\n"
        code += "return NULL;\n"
        code += "}\n"
        code += "}\n\n"

        code += include_file("handwritten/hexagon_c/functions.c")

        self.write_src(code, path)

    # RIZIN SPECIFIC
    def build_asm_hexagon_c(self, path: str = "./rizin/librz/asm/p/asm_hexagon.c") -> None:
        code = get_generation_warning_c_code()

        code += include_file("handwritten/asm_hexagon_c/include.c")
        code += include_file("handwritten/asm_hexagon_c/initialization.c")

        self.write_src(code, path)

    # RIZIN SPECIFIC
    def build_hexagon_arch_c(self, path: str = "./rizin/librz/asm/arch/hexagon/hexagon_arch.c"):
        code = get_generation_warning_c_code()

        code += include_file("handwritten/hexagon_arch_c/include.c")
        code += include_file("handwritten/hexagon_arch_c/functions.c")

        self.write_src(code, path)

    # RIZIN SPECIFIC
    def build_hexagon_arch_h(self, path: str = "./rizin/librz/asm/arch/hexagon/hexagon_arch.h"):
        code = get_generation_warning_c_code()
        code += get_include_guard("hexagon_arch.h")

        code += include_file("handwritten/hexagon_arch_h/includes.h")
        code += include_file("handwritten/hexagon_arch_h/typedefs.h")
        code += include_file("handwritten/hexagon_arch_h/declarations.h")
        code += "#endif"

        self.write_src(code, path)

    # RIZIN SPECIFIC
    @staticmethod
    def copy_tests() -> None:
        with open("handwritten/analysis-tests/hexagon") as f:
            with open("./rizin/test/db/analysis/hexagon", "w+") as g:
                set_pos_after_license(g)
                g.writelines(f.readlines())

        with open("handwritten/asm-tests/hexagon") as f:
            with open("./rizin/test/db/asm/hexagon", "w+") as g:
                set_pos_after_license(g)
                g.writelines(f.readlines())
        log("Copied test files to ./rizin/test/db/", LogLevel.DEBUG)

    # RIZIN SPECIFIC
    def build_analysis_hexagon_c(self, path: str = "./rizin/librz/analysis/p/analysis_hexagon.c") -> None:
        """Generates and writes the register profile.
        Note that some registers share the same offsets. R0 and R1:0 are both based at offset 0.
        """
        profile = self.get_alias_profile().splitlines(keepends=True)
        tmp_regs = []  # Tmp register for RZIL
        reg_offset = 0
        offsets = {"IntRegs": 0}
        offsets["CtrRegs"] = offsets["IntRegs"] + len(self.hardware_regs["IntRegs"]) * 32
        offsets["GuestRegs"] = offsets["CtrRegs"] + len(self.hardware_regs["CtrRegs"]) * 32
        offsets["HvxQR"] = offsets["GuestRegs"] + len(self.hardware_regs["GuestRegs"]) * 32
        offsets["HvxVR"] = offsets["HvxQR"] + len(self.hardware_regs["HvxQR"]) * 128
        offsets["SysRegs"] = offsets["HvxVR"] + len(self.hardware_regs["HvxVR"]) * 1024
        offsets["TmpRegs"] = offsets["SysRegs"] + len(self.hardware_regs["SysRegs"]) * 32

        for hw_reg_class in self.hardware_regs:
            if hw_reg_class in [
                "IntRegsLow8",
                "GeneralSubRegs",
                "GeneralDoubleLow8Regs",
                "ModRegs",
            ]:
                continue  # Those registers would only be duplicates.
            if hw_reg_class in ["IntRegs", "DoubleRegs"]:
                reg_offset = offsets["IntRegs"]
            elif hw_reg_class in ["CtrRegs", "CtrRegs64"]:
                reg_offset = offsets["CtrRegs"]
            elif hw_reg_class == "PredRegs":
                reg_offset = offsets["CtrRegs"] + (32 * 4)  # PredRegs = C4
            elif hw_reg_class in ["GuestRegs", "GuestRegs64"]:
                reg_offset = offsets["GuestRegs"]
            elif hw_reg_class in ["HvxVR", "HvxWR", "HvxVQR"]:
                reg_offset = offsets["HvxVR"]
            elif hw_reg_class == "HvxQR":
                reg_offset = offsets["HvxQR"]
            elif hw_reg_class in ["SysRegs", "SysRegs64"]:
                reg_offset = offsets["SysRegs"]
            else:
                raise ImplementationException(
                    "Register profile can't be completed. Base for type {} missing.".format(hw_reg_class)
                )

            hw_reg: HardwareRegister
            for hw_reg in {
                k: v for k, v in sorted(self.hardware_regs[hw_reg_class].items(), key=lambda item: item[1])
            }.values():
                profile.append(hw_reg.get_reg_profile(reg_offset, False) + "\n")
                tmp_regs.append(hw_reg.get_reg_profile(reg_offset + offsets["TmpRegs"], True) + "\n")
                reg_offset += hw_reg.size if not (hw_reg.llvm_reg_class == "PredRegs") else 8
            profile.append("\n")
        profile = profile + tmp_regs
        profile = profile[:-1]  # Remove line breaks
        profile[-1] = profile[-1][:-1] + ";\n"  # [:-1] to remove line break.

        code = get_generation_warning_c_code()

        code += include_file("handwritten/analysis_hexagon_c/include.c")
        code += include_file("handwritten/analysis_hexagon_c/functions.c")

        tmp = list()
        tmp.append("const char *p =")
        tmp += profile
        tmp = make_c_block(
            lines=tmp,
            begin="RZ_API char *get_reg_profile(RzAnalysis *analysis)",
            ret="return strdup(p);",
        )
        code += "\n" + "".join(tmp)

        code += include_file("handwritten/analysis_hexagon_c/initialization.c")

        self.write_src(code, path)

    # RIZIN SPECIFC
    def get_alias_profile(self) -> str:
        """Returns the alias profile of register. A0 = R0, SP = R29 PC = pc etc."""
        indent = PluginInfo.LINE_INDENT

        p = "\n" + '"=PC{}pc\\n"'.format(indent) + "\n"
        p += '"=SP{}R29\\n"'.format(indent) + "\n"
        p += '"=BP{}R30\\n"'.format(indent) + "\n"
        p += '"=LR{}R31\\n"'.format(indent) + "\n"
        p += '"=SR{}C8\\n"'.format(indent) + "\n"
        p += '"=SN{}R0\\n"'.format(indent) + "\n"

        arg_regs = ""
        ret_regs = ""

        arguments = HexagonArchInfo.CC_REGS["GPR_args"]
        returns = HexagonArchInfo.CC_REGS["GPR_ret"]

        general_ps = list(self.hardware_regs["IntRegs"].values())
        gpr: HardwareRegister
        for gpr in general_ps:
            try:
                i = arguments.index(gpr.name)
            except ValueError:
                continue
            if i > 9 and gpr.name in HexagonArchInfo.CC_REGS["GPR_args"]:
                log(
                    "Can not add register {} as argument reg to the register"
                    " profile. ".format(gpr.name) + "Rizin only supports 10 argument registers. Check"
                    " rz_reg.h if this changed.",
                    LogLevel.WARNING,
                )
            if gpr.name in HexagonArchInfo.CC_REGS["GPR_args"]:
                arg_regs += '"=A{}{}{}\\n"'.format(i, indent, gpr.asm_name.upper()) + "\n"

        for gpr in general_ps:
            try:
                i = returns.index(gpr.name)
            except ValueError:
                continue
            if i > 3 and gpr.name in HexagonArchInfo.CC_REGS["GPR_ret"]:
                log(
                    "Can not add register {} as return reg to the register"
                    " profile. ".format(gpr.name) + "Rizin only supports 4 return registers. Check rz_reg.h"
                    " if this changed.",
                    LogLevel.WARNING,
                )
            if gpr.name in HexagonArchInfo.CC_REGS["GPR_ret"]:
                ret_regs += '"=R{}{}{}\\n"'.format(i, indent, gpr.asm_name.upper()) + "\n"

        p += arg_regs + ret_regs + "\n"

        return p

    # RIZIN SPECIFIC
    @staticmethod
    def build_cc_hexagon_32_sdb_txt(
        path: str = "rizin/librz/analysis/d/cc-hexagon-32.sdb.txt",
    ) -> None:
        """Builds the *incomplete* calling convention as sdb file.
        Hexagon can pass arguments and return values via different registers. E.g. either over R0 or R1:0.
        But the calling convention logic in rizin and the sdb is not sophisticated enough to model this.
        That is the reason we add only one of multiple possible argument/return register per db entry.
        """

        cc_dict = dict()
        with open(path, "w+") as f:
            for reg in HexagonArchInfo.CC_REGS["GPR_args"]:
                n = int(re.search(r"\d{1,2}", reg).group(0))
                if reg[0] == "R":
                    cc_dict["cc.hexagon.arg{}".format(n)] = "r{}".format(n)
                elif reg[0] == "D":
                    continue
                else:
                    raise ImplementationException(
                        "Could not assign register {} to a specific argument" " value.".format(reg)
                    )
            cc_dict["cc.hexagon.argn"] = "stack_rev"
            for reg in HexagonArchInfo.CC_REGS["GPR_ret"]:
                n = int(re.search(r"\d{1,2}", reg).group(0))
                if reg[0] == "R":
                    if HexagonArchInfo.CC_REGS["GPR_ret"].index(reg) == 0:
                        cc_dict["cc.hexagon.ret".format(n)] = "r{}".format(n)
                    else:
                        continue
                elif reg[0] == "D":
                    continue
                else:
                    raise ImplementationException(
                        "Could not assign register {} to a specific return" " value.".format(reg)
                    )

            f.write("default.cc=hexagon\n\nhexagon=cc\n")
            for k, v in cc_dict.items():
                f.write(k + "=" + v + "\n")
            f.write("\nhvx=cc\ncc.hvx.name=hvx\n")

            cc_dict = dict()
            for reg in HexagonArchInfo.CC_REGS["HVX_args"]:
                n = int(re.search(r"\d{1,2}", reg).group(0))
                if reg[0] == "V":
                    cc_dict["cc.hvx.arg{}".format(n)] = "v{}".format(n)
                elif reg[0] == "W":
                    continue
                else:
                    raise ImplementationException(
                        "Could not assign register {} to a specific argument" " value.".format(reg)
                    )
            for reg in HexagonArchInfo.CC_REGS["HVX_ret"]:
                n = int(re.search(r"\d{1,2}", reg).group(0))
                if reg[0] == "V":
                    if HexagonArchInfo.CC_REGS["HVX_ret"].index(reg) == 0:
                        cc_dict["cc.hvx.ret".format(n)] = "v{}".format(n)
                    else:
                        continue
                elif reg[0] == "W":
                    continue
                else:
                    raise ImplementationException(
                        "Could not assign register {} to a specific return" " value.".format(reg)
                    )
            for k, v in cc_dict.items():
                f.write(k + "=" + v + "\n")

    # RIZIN SPECIFIC
    @staticmethod
    def apply_clang_format() -> None:
        log("Apply clang-format.")
        for subdir, dirs, files in os.walk("rizin/librz/"):
            for file in files:
                p = os.path.join(subdir, file)
                if os.path.splitext(p)[-1] in [
                    ".c",
                    ".cpp",
                    ".h",
                    ".hpp",
                    ".inc",
                ]:
                    log("Format {}".format(p), LogLevel.VERBOSE)
                    os.system("clang-format-13 -style file -i " + p)

    def write_src(self, code: str, path: str) -> None:
        """Compares the given src code to the src code in the file at path and writes it if it differs.
        It ignores the leading license header and timestamps in the existing src file.
        Changes in formatting (anything which matches the regex '[[:blank:]]')
        """

        if compare_src_to_old_src(code, path):
            self.unchanged_files.append(path)
            return
        with open(path, "w+") as dest:
            dest.writelines(code)
            log("Write {}".format(path), LogLevel.INFO)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Import settings")
    parser.add_argument(
        "-j",
        action="store_true",
        default=False,
        help="Run llvm-tblgen to build a new Hexagon.json file from the LLVM definitons.",
        dest="bjs",
    )
    args = parser.parse_args()
    interface = LLVMImporter(args.bjs)
