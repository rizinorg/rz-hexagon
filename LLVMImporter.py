#!/usr/bin/env python3
import argparse

# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import json
import os
import re
import subprocess
from pathlib import Path

from tqdm import tqdm

from Conf import OutputFile, Conf
from rzil_compiler.Transformer.Hybrids.SubRoutine import SubRoutineInitType
from rzil_compiler.ArchEnum import ArchEnum
from rzil_compiler.Compiler import Compiler, RZILInstruction
from HardwareRegister import HardwareRegister
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
    src_matches_old_src,
    include_file,
    gen_c_doxygen, get_delimiter_line,
)
import PluginInfo
import HexagonArchInfo
from InstructionTemplate import PARSE_BITS_MASK_CONST, InstructionTemplate


class LLVMImporter:
    config = dict()
    hexArch = dict()
    hexagon_target_json_path = ""
    llvm_instructions = dict()
    normal_instruction_names = list()
    normal_instructions = dict()
    sub_instruction_names = list()
    sub_instructions = dict()
    hardware_regs = dict()
    rzil_compiler = None
    edited_files: [str] = list()

    def __init__(self, build_json: bool, gen_rzil: bool, skip_pcpp: bool, rzil_compile: bool, test_mode=False):
        self.gen_rzil = gen_rzil
        self.rzil_compile = rzil_compile
        self.sub_namespaces = set()
        self.skip_pcpp = skip_pcpp
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

        if self.gen_rzil:
            self.setup_rzil_compiler()

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

        # Name of the function which parses the encoded register index bits.
        self.reg_resolve_decl = list()

        self.parse_hardware_registers()
        self.parse_instructions()
        self.check_insn_syntax_length()
        if not test_mode:
            self.generate_rizin_code()
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
                    config += "LLVM_PROJECT_REPO_DIR = /path/to/llvm_project\n"
                    config += "CLANG_FORMAT_BIN = clang-format-18"
                    f.write(config)
                log(
                    f"This is your first time running the generator{' TESTS' if self.test_mode else ''}."
                    + f" Please set the path to the llvm_project repo and clang-format binary in {cwd}/.config."
                )
                exit()
            with open(cwd + "/.config") as f:
                for line in f.readlines():
                    ln = line.strip()
                    if ln[0] == "#":
                        continue
                    ln = ln.split("=")
                    if ln[0].strip() == "LLVM_PROJECT_REPO_DIR":
                        conf_value = ln[1].strip()
                        if not os.path.exists(conf_value):
                            log(
                                f"The LLVM_PROJECT_REPO_DIR is set to an invalid directory: '{conf_value}'",
                                LogLevel.ERROR,
                            )
                            exit()
                        self.config["LLVM_PROJECT_REPO_DIR"] = conf_value
                        self.config["LLVM_PROJECT_HEXAGON_DIR"] = conf_value + "/llvm/lib/Target/Hexagon"
                    elif ln[0].strip() == "CLANG_FORMAT_BIN":
                        conf_value = ln[1].strip()
                        self.config["CLANG_FORMAT_BIN"] = conf_value
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

    def setup_rzil_compiler(self):
        log("Init compiler")
        self.rzil_compiler = Compiler(ArchEnum.HEXAGON)
        if not self.skip_pcpp:
            self.rzil_compiler.run_preprocessor()

        log("Load instruction behavior.")
        self.rzil_compiler.preprocessor.load_insn_behavior()

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
            reg_class = ""
            if len(filename.split("-")) == 2:
                reg_class = filename.split("-")[0]
            with open(reg_dir + filename) as f:
                reg = json.load(f)
            reg_name = list(reg.keys())[0]
            if reg_name in self.hexArch["!instanceof"]["DwarfRegNum"]:
                raise ValueError(
                    f"Register {reg_name} already present in the LLVM definitions."
                    " Please check whether LLVM defines it."
                )
            self.hexArch["!instanceof"]["DwarfRegNum"] += reg.keys()
            reg_count += 1
            self.hexArch.update(reg)
            if reg_class:
                arg = {"def": reg_name, "kind": "def", "printable": reg_name}
                self.hexArch[reg_class]["MemberList"]["args"].append([arg, None])

        instr_count = 0
        insn_dir = "./import/instructions/" if not self.test_mode else "../import/instructions/"
        for filename in sorted(os.listdir(insn_dir)):
            if filename.split(".")[-1] != "json":
                continue
            instn_name = filename.replace(".json", "")
            with open(insn_dir + filename) as f:
                insn = json.load(f)
            syntax_list = dict()
            for llvm_instr in self.hexArch["!instanceof"]["HInst"]:
                syntax_list[llvm_instr] = self.hexArch[llvm_instr]["AsmString"]
            if "UNDOCUMENTED" not in instn_name and insn[instn_name]["AsmString"] in syntax_list.values():
                if self.obsolete_import_handler(filename, insn, instn_name, syntax_list):
                    continue
            self.hexArch.update(insn)
            self.hexArch["!instanceof"]["HInst"] += list(insn.keys())
            instr_count += 1
        log("Imported {} registers.".format(reg_count))
        log("Imported {} instructions.".format(instr_count))

    def obsolete_import_handler(self, filename, insn, instn_name, syntax_list) -> bool:
        """
        Handles the case of an imported instruction becoming obsolete because it was
        added to LLVM.
        :return: True if the encodings match. False otherwise.
        """
        name_idx = list(syntax_list.values()).index(insn[instn_name]["AsmString"])
        llvm_insn_name = self.hexArch["!instanceof"]["HInst"][name_idx]
        imported_enc = insn[instn_name]["Inst"]
        llvm_enc = self.hexArch[llvm_insn_name]["Inst"]
        encodings_match = True
        cleaned_llvm_enc = list()
        for imp_bit, llvm_bit in zip(imported_enc, llvm_enc):
            if isinstance(imp_bit, dict) and isinstance(llvm_bit, dict):
                if imp_bit["var"] != llvm_bit["var"]:
                    encodings_match = False
            elif imp_bit != llvm_bit:
                encodings_match = False

            if isinstance(llvm_bit, dict):
                del llvm_bit["kind"]
                del llvm_bit["printable"]
            cleaned_llvm_enc.append(llvm_bit)
        if encodings_match:
            log(
                "Imported instruction was added to LLVM.\n"
                f"\tInstr.: '{instn_name}' -> '{llvm_insn_name}'\n"
                f"\tRemove: {filename}"
            )
            return True
        log(
            "Imported instruction was added to LLVM. But the encodings mismatch!\n"
            f"\tInstr.: '{instn_name}' -> '{llvm_insn_name}'\n"
            f"\tImported enc: {imported_enc}\n"
            f"\tLLVM enc:     {llvm_enc}",
            LogLevel.WARNING,
        )
        return False

    def skip_insn(self, insn_name: str) -> bool:
        # PS_ instructions are pseudo instructions, but not marked as such.
        # They do not exist in QEMU.
        if insn_name.lower().startswith("ps"):
            return True
        return False

    def parse_instructions(self) -> None:
        compiled_insn = 0
        hvx_compiled = 0
        standard_compiled = 0
        # Filter out pseudo instructions
        no_pseudo = [
            i for i in self.hexArch["!instanceof"]["HInst"] if not self.hexArch[i]["isPseudo"] and not self.skip_insn(i)
        ]
        if self.gen_rzil and self.rzil_compile:
            self.rzil_compiler.parse_shortcode()

        with tqdm(
            desc="Parse instructions.",
            postfix=f"Succ. compiled: {compiled_insn}/{len(no_pseudo)}",
            total=len(no_pseudo),
        ) as t:
            for i, i_name in enumerate(no_pseudo):
                llvm_instruction = self.hexArch[i_name]
                if llvm_instruction is None:
                    log("Could not find instruction with name: {} in json file.".format(i_name), LogLevel.ERROR)
                    continue
                log("{} | Parse {}".format(i, i_name), LogLevel.VERBOSE)
                self.llvm_instructions[i_name] = llvm_instruction

                if llvm_instruction["Type"]["def"] == "TypeSUBINSN":
                    self.sub_instruction_names.append(i_name)
                    insn = SubInstruction(llvm_instruction)
                    self.sub_instructions[i_name] = insn
                    ns = self.sub_instructions[i_name].namespace
                    if ns not in self.sub_namespaces:
                        self.sub_namespaces.add(ns)
                else:
                    self.normal_instruction_names.append(i_name)
                    insn = Instruction(llvm_instruction)
                    self.normal_instructions[i_name] = insn
                if self.gen_rzil and self.rzil_compile:
                    log("{} | Compile {}".format(i, i_name), LogLevel.VERBOSE)
                    if self.set_il_op(insn):
                        if i_name[:2] == "V6":
                            hvx_compiled += 1
                        else:
                            standard_compiled += 1
                        compiled_insn += 1
                else:
                    insn.il_ops = RZILInstruction.get_unimplemented_rzil_instr(insn.name)
                t.n = i
                t.postfix = f"Succ. compiled: {compiled_insn}/{len(no_pseudo)}"
                t.update()
        self.rzil_compiler.transformer.ext.report_missing_fcns()

        log("Parsed {} normal instructions.".format(len(self.normal_instructions)))
        log("Parsed {} sub-instructions.".format(len(self.sub_instructions)))
        if self.gen_rzil and self.rzil_compile:
            total = len(self.normal_instruction_names) + len(self.sub_instruction_names)
            total_hvx = len([n for n in self.normal_instruction_names if n[:2] == "V6"])
            total_standard = total - total_hvx
            log(f"{standard_compiled}/{total_standard} standard instructions compiled.")
            log(f"{hvx_compiled}/{total_hvx} HVX instructions compiled.")
            log(f"In total: {compiled_insn}/{total} instructions compiled.")

    def set_il_op(self, insn: InstructionTemplate) -> bool:
        try:
            insn.il_ops = self.rzil_compiler.compile_insn(insn.name)
            return True
        except Exception as e:
            log(f"Failed to compile instruction {insn.name}\nException: {e}\n", LogLevel.DEBUG)
            # Compiler failure for instruction or not implemented
            insn.il_ops = RZILInstruction.get_unimplemented_rzil_instr(insn.name)
            return False

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
                # Remove registers which start with WR; WR register are reverse double vector regs: V0:1 instead of V1:0
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
            self.sub_instructions.values(),
        ]:
            for insn in instr_set:
                if len(insn.syntax) >= 128:
                    sl = len(insn.syntax) + 1  # +1 for \0 in the string
                    raise ImplementationException(
                        "The text infix variable is at the moment only 128 byte."
                        + "This syntax takes at least {}+1 bytes.".format(sl)
                    )

    def get_cc_regs(self) -> dict:
        """Returns a list of register names which are argument or return register in the calling convention.
        This part is a bit tricky. The register names are stored in objects named "anonymous_XXX" in Hexagon.json.
        Since they do not have an explicit name, we can only check the names against the source.

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

    def generate_rizin_code(self) -> None:
        log("Generate and write source code.")
        self.build_hexagon_insn_enum_h()
        self.build_hexagon_disas_c()
        self.build_hexagon_c()
        self.build_hexagon_h()
        self.build_dwarf_reg_num_table()
        self.build_hexagon_reg_tables_h()
        self.build_asm_hexagon_c()
        self.build_hexagon_arch_c()
        self.build_hexagon_arch_h()
        self.build_hexagon_il_h()
        self.build_hexagon_il_getter_table_h()
        self.build_hexagon_il_c()
        self.build_hexagon_il_X_ops_c()
        self.copy_tests()
        self.build_analysis_hexagon_c()
        self.build_cc_hexagon_32_sdb_txt()

        # TODO hexagon.h: Gen - HexOpType, IClasses, Regs and its aliases (system = guest),
        #  + corresponding functions in hexagon.c: hex_get_sub_regpair etc.

    # TODO Wouldn't it be a wonderful world...
    def generate_decompiler_code(self) -> None:
        pass

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

                    # If header message is there, skip it.
                    match = re.search(get_delimiter_line(), content)
                    if match:
                        content = content[match.start():]
                    f.write(get_license() + "\n" + get_generation_timestamp(self.config) + "\n" + content)
                if p not in self.edited_files:
                    log("Write {}".format(p), LogLevel.INFO)

    def build_hexagon_il_h(self, path: Path = Conf.get_path(OutputFile.HEXAGON_IL_H)) -> None:
        if not self.gen_rzil:
            self.unchanged_files.append(path)
            return
        code = get_generation_warning_c_code()
        code += "\n"
        code += get_include_guard("hexagon_il.h")
        code += "\n"

        code += include_file("handwritten/hexagon_il_h/includes.h")
        code += "\n"

        code += include_file("handwritten/hexagon_il_h/macros.h")
        code += "\n"

        code += include_file("handwritten/hexagon_il_h/declarations.h")

        # Getter declarations
        for insn in list(self.normal_instructions.values()) + list(self.sub_instructions.values()):
            for fcn_decl in insn.il_ops["getter_rzil"]["fcn_decl"]:
                code += f"{fcn_decl};\n"

        with open("handwritten/misc_il_insns.json") as f:
            misc_insns = json.loads(f.read())

        for name in misc_insns["qemu_defined"]:
            rzil_insn = self.rzil_compiler.compile_insn(name)
            for decl in rzil_insn["getter_rzil"]["fcn_decl"]:
                code += f"{decl};\n"

        for routine_name, routine in self.rzil_compiler.sub_routines.items():
            sub_routine = self.rzil_compiler.get_sub_routine(routine_name)
            code += f"{sub_routine.il_init(SubRoutineInitType.DECL)};\n"

        code += "\n#endif\n"

        self.write_src(code, path)

    def build_hexagon_il_c(self, path: Path = Conf.get_path(OutputFile.HEXAGON_IL_C)) -> None:
        if not self.gen_rzil:
            self.unchanged_files.append(path)
            return
        code = get_generation_warning_c_code()
        code += "\n"

        code += include_file("handwritten/hexagon_il_c/includes.c")
        code += "\n"

        code += include_file("handwritten/hexagon_il_c/functions.c")
        code += "\n"
        code += include_file("handwritten/hexagon_il_c/exclude.c")

        self.write_src(code, path)

    def get_il_op_c_defintion(self, syntax: str, rzil_insn: RZILInstruction) -> str:
        code = ""
        for rzil_code, fcn_decl, needs_hi, needs_pkt in zip(
            rzil_insn["rzil"], rzil_insn["getter_rzil"]["fcn_decl"], rzil_insn["needs_hi"], rzil_insn["needs_pkt"]
        ):
            code += f"// {syntax}\n"
            code += f"{fcn_decl} {{"

            if needs_hi:
                code += "const HexInsn *hi = bundle->insn;"
            if needs_pkt:
                code += "HexPkt *pkt = bundle->pkt;"

            code += rzil_code
            code += "}\n\n"
        return code

    def build_hexagon_il_X_ops_c(self, path: Path = Conf.get_path(OutputFile.IL_OPS_DIR)) -> None:
        """Generate the IL op getter for each instruction.
        The file the getter is written to depend on the instruction class.
        Args:
            path: Path to directory where the src files will be written.

        Returns: None
        """
        if not (self.gen_rzil and self.rzil_compile):
            for subdir, _, files in os.walk(path):
                for file in files:
                    self.unchanged_files.append(os.path.join(subdir, file))
            return
        insns = dict()
        # Bundle instructions by category
        for i_name in sorted(self.normal_instruction_names + self.sub_instruction_names):
            insn = (
                self.normal_instructions[i_name]
                if i_name in self.normal_instruction_names
                else self.sub_instructions[i_name]
            )
            try:
                # category: A2, SA1 etc.
                category = re.search(r"^([a-zA-Z\d]+)_", insn.name).group(1)
            except Exception as e:
                print(insn.name)
                raise e
            if category in insns:
                insns[category].append(insn)
            else:
                insns[category] = [insn]

        for cp in insns.keys():
            code = get_generation_warning_c_code()
            code += include_file("handwritten/hexagon_il_X_ops_c/includes.h") + "\n"
            for insn in insns[cp]:
                code += self.get_il_op_c_defintion(insn.syntax, insn.il_ops)
            code += include_file("handwritten/hexagon_il_X_ops_c/excludes.h")
            self.write_src(code, path.joinpath(f"hexagon_il_{cp}_ops.c"))

        self.gen_misc_instructions(path)

    def gen_misc_instructions(self, path: Path = Conf.get_path(OutputFile.IL_OPS_DIR)) -> None:
        code = get_generation_warning_c_code()
        code += include_file("handwritten/hexagon_il_X_ops_c/includes.h") + "\n"

        with open("handwritten/misc_il_insns.json") as f:
            misc_insns = json.loads(f.read())

        for name in misc_insns["qemu_defined"]:
            rzil_insn = self.rzil_compiler.compile_insn(name)
            if name in self.normal_instructions:
                syntax = self.normal_instructions[name]
            elif name in self.sub_instructions:
                syntax = self.sub_instructions[name]
            else:
                syntax = "No syntax"
            code += self.get_il_op_c_defintion(syntax, rzil_insn)

        for routine_name, routine in self.rzil_compiler.sub_routines.items():
            sub_routine = self.rzil_compiler.get_sub_routine(routine_name)
            code += sub_routine.il_init(SubRoutineInitType.DEF) + "\n\n"

        code += include_file("handwritten/hexagon_il_X_ops_c/non_insn_ops.c")
        code += include_file("handwritten/hexagon_il_X_ops_c/excludes.h")
        self.write_src(code, path.joinpath("hexagon_il_non_insn_ops.c"))

    def build_hexagon_insn_enum_h(self, path: Path = Conf.get_path(OutputFile.HEXAGON_INSN_H)) -> None:
        code = get_generation_warning_c_code()
        code += "\n"
        code += get_include_guard("hexagon_insn.h")
        code += "\ntypedef enum {\n"
        enum = ""
        for name in sorted(self.normal_instruction_names + self.sub_instruction_names):
            if "invalid_decode" in name:
                enum = (PluginInfo.INSTR_ENUM_PREFIX + name.upper() + " = 0,") + enum
            else:
                enum += PluginInfo.INSTR_ENUM_PREFIX + name.upper() + ","
        code += enum
        code += "} HexInsnID;\n"
        code += "#endif"

        self.write_src(code, path)

    def build_hexagon_disas_c(self, path: Path = Conf.get_path(OutputFile.HEXAGON_DISAS_C)) -> None:
        code = get_generation_warning_c_code()

        code += include_file("handwritten/hexagon_disas_c/include.c")
        code += include_file("handwritten/hexagon_disas_c/types.c")

        templates_code = "\n\n"

        # Sub-Instructions instructions
        for ns in sorted(self.sub_namespaces):
            templates_code += f"static const HexInsnTemplate templates_sub_{ns.name}[] = {{\n"
            instr: SubInstruction
            for instr in self.sub_instructions.values():
                if instr.namespace == ns:
                    templates_code += instr.get_template_in_c() + ","
            templates_code += "{ { 0 } }, };\n\n"

        # Normal instructions
        for c in range(0x10):
            templates_code += f"static const HexInsnTemplate templates_normal_0x{c:x}[] = {{\n"
            instr: Instruction
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

    def build_hexagon_il_getter_table_h(self, path: Path = Conf.get_path(OutputFile.HEXAGON_IL_GETTER_TABLE_H)) -> None:
        if not self.gen_rzil:
            self.unchanged_files.append(path)
            return
        code = get_generation_warning_c_code()
        code += "\n"
        code += get_include_guard("hexagon_il_getter_table.h")
        code += "\n"
        code += include_file("handwritten/hexagon_il_getter_table_h/includes.h")
        code += "\n"

        # Lookup table
        code += "static HexILInsn hex_il_getter_lt[] = {\n"
        table = ""
        for name in sorted(self.normal_instruction_names + self.sub_instruction_names):
            insn = self.normal_instructions[name] if name in self.normal_instructions else self.sub_instructions[name]
            if "invalid_decode" in name.lower():
                # Invalid decode is always at the top.
                tmp = f"{{{{(HexILOpGetter) {insn.il_ops['getter_rzil']['name'][0]}, {insn.il_ops['meta'][0][0]}}},\n"
                tmp += "{(HexILOpGetter) NULL, HEX_IL_INSN_ATTR_INVALID},\n"
                tmp += "{(HexILOpGetter) NULL, HEX_IL_INSN_ATTR_INVALID}\n"
                tmp += "},"
                table = tmp + table
                continue
            members_to_set = PluginInfo.NUM_HEX_IL_INSN_MEMBERS
            getter: str
            meta: [str]
            table += "{"
            for getter, meta in zip(insn.il_ops["getter_rzil"]["name"], insn.il_ops["meta"]):
                table += f"{{(HexILOpGetter) {getter}, {'|'.join(meta)}}},\n"
                members_to_set -= 1
            if members_to_set < 1:
                log("Can not set more than two IL operations. Please add more members to HexILInsn.", LogLevel.ERROR)
            if members_to_set == 1:
                table += "{(HexILOpGetter) NULL, HEX_IL_INSN_ATTR_INVALID}\n"
            else:
                table += "{(HexILOpGetter) NULL, HEX_IL_INSN_ATTR_INVALID},\n"
                table += "{(HexILOpGetter) NULL, HEX_IL_INSN_ATTR_INVALID}\n"

            table += "},"
        code += table + "};"

        code += "\n#endif"
        self.write_src(code, path)

    def build_hexagon_reg_tables_h(self, path: Path = Conf.get_path(OutputFile.HEXAGON_REG_TABLES_H)) -> None:
        code = get_generation_warning_c_code()
        code += "\n"
        code += get_include_guard("hexagon_reg_tables.h")
        code += "\n"
        code += include_file("handwritten/hexagon_reg_tables_h/includes.h")
        code += "\n"

        code += self.gen_alias_lt()
        code += self.get_reg_name_tables()

        code += "\n#endif"
        self.write_src(code, path)

    def build_hexagon_h(self, path: Path = Conf.get_path(OutputFile.HEXAGON_H)) -> None:
        code = get_generation_warning_c_code()
        code += "\n"
        code += get_include_guard("hexagon.h")
        code += "\n"

        code += include_file("handwritten/hexagon_h/includes.h")
        code += "\n"

        code += include_file("handwritten/hexagon_h/macros.h")
        code += "\n"

        code += f"#define {PluginInfo.GENERAL_ENUM_PREFIX}MAX_OPERANDS {PluginInfo.MAX_OPERANDS}\n"
        code += f"#define {PluginInfo.GENERAL_ENUM_PREFIX}PARSE_BITS_MASK 0x{PARSE_BITS_MASK_CONST:x}\n\n"
        code += include_file("handwritten/hexagon_h/typedefs.h")
        code += "\n"

        code += "typedef enum {\n"
        code += ",\n".join([HardwareRegister.get_enum_item_of_class(reg_class) for reg_class in self.hardware_regs])
        code += "} HexRegClass;\n\n"

        code += self.gen_reg_enums()
        code += self.gen_alias_enum()

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

    def get_reg_name_tables(self) -> str:
        """
        Generates the lookup tables of register names, alias and their corresponding .new names (<name>_tmp).
        Each hardware register has a specific number, with which it is identified in the opcode
        (HardwareRegister.hw_encoding).
        The index of a hardware registers name, alias and .new names is calculated like following:

        reg_name_index = HardwareRegister.hw_encoding
        alias_index = reg_name_index + 1
        reg_name_new_index = reg_name_index + 2
        alias_new_index = reg_name_index + 3

        Note: The hw_encoding values does not necessarily increment by one.
        Lines which have no index due to that are filled with NULL.

        Returns: The C code with lookup tables for each register class.
        """
        code = ""
        for reg_class in self.hardware_regs:
            code += "\n\n" + gen_c_doxygen(f"Lookup table for register names and alias of class {reg_class}.")
            table_name = PluginInfo.REGISTER_LOOKUP_TABLE_NAME_V69.format(reg_class.lower())
            code += f"HexRegNames {table_name}[] = {{\n"

            index = 0
            hw_reg: HardwareRegister
            for hw_reg in sorted(
                self.hardware_regs[reg_class].values(),
                key=lambda x: x.hw_encoding,
            ):
                while index < hw_reg.hw_encoding:
                    code += f"{{NULL, NULL, NULL, NULL}}, // -\n"
                    index += 1
                name = hw_reg.asm_name
                alias = hw_reg.alias[0] if len(hw_reg.alias) > 0 else hw_reg.asm_name
                code += f'{{"{name.upper()}", "{alias.upper()}", "{name.upper()}_tmp", "{alias}_tmp"}}, // {hw_reg.enum_name}\n'
                index += 1
            code += "};\n"
        return code

    def get_hw_alias(self) -> [dict]:
        """
        Generates the list with alias of hardware registers and all the information about each alias.
        Used to generate alias enums and lookup tables.
        """
        alias = list()
        for reg_class in self.hardware_regs:
            hw_reg: HardwareRegister
            for hw_reg in sorted(self.hardware_regs[reg_class].values(), key=lambda x: x.hw_encoding):
                if hw_reg.is_mod:
                    # Alias already set for c0, c1
                    continue
                if len(hw_reg.alias) == 0:
                    continue
                for a in hw_reg.alias:
                    alias.append(
                        {
                            "alias_enum": f'{PluginInfo.REGISTER_ALIAS_ENUM_PREFIX}{re.sub(r":", "_", a).upper()}',
                            "reg_class": hw_reg.get_enum_item_of_class(reg_class),
                            "reg_enum": hw_reg.enum_name,
                            "real": hw_reg.asm_name,
                        }
                    )
        return alias

    def gen_alias_lt(self) -> str:
        """
        Generates the lookup table for all know register alias.
        Returns: C lookup table with register alias.
        """
        code = gen_c_doxygen("Lookup table for register alias.\n")
        code += f"HexRegAliasMapping {PluginInfo.ALIAS_REGISTER_LOOKUP_TABLE_v69}[] = {{\n"
        code += "\n".join(
            [f'{{{a["reg_class"]}, {a["reg_enum"]}}}, // {a["alias_enum"]}' for i, a in enumerate(self.get_hw_alias())]
        )
        code += "\n};\n\n"
        return code

    def gen_alias_enum(self) -> str:
        """
        Generates the enum for all know register alias.
        Returns: C enum with register alias.
        """
        code = "typedef enum {\n"
        code += "".join([a["alias_enum"] + f" = {i},\n" for i, a in enumerate(self.get_hw_alias())])
        code += "} HexRegAlias;\n\n"
        return code

    def gen_reg_enums(self) -> str:
        code = ""
        reg_class: str
        for reg_class in self.hardware_regs:
            code += "typedef enum {\n"

            hw_reg: HardwareRegister
            for hw_reg in sorted(
                self.hardware_regs[reg_class].values(),
                key=lambda x: x.hw_encoding,
            ):
                alias = ",".join(hw_reg.alias)
                code += "{} = {},{}".format(
                    hw_reg.enum_name,
                    hw_reg.hw_encoding,
                    " // " + alias + "\n" if alias != "" else "\n",
                )
            code += "}} {}{}; // {}\n\n".format(
                PluginInfo.GENERAL_ENUM_PREFIX,
                HardwareRegister.register_class_name_to_upper(reg_class),
                reg_class,
            )
        return code

    def build_hexagon_c(self, path: Path = Conf.get_path(OutputFile.HEXAGON_C)) -> None:
        general_prefix = PluginInfo.GENERAL_ENUM_PREFIX
        code = get_generation_warning_c_code()
        code += include_file("handwritten/hexagon_c/include.c")
        code += "\n"

        code += self.gen_resolve_reg_enum_id_fcn()
        code += "\n"
        code += self.gen_get_reg_name_fcns()
        code += "\n"

        reg_in_cls_decl = (
            f"RZ_API const char *{general_prefix.lower()}"
            "get_reg_in_class(HexRegClass cls, int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum)"
        )
        self.reg_resolve_decl.append(f"{reg_in_cls_decl};")
        code += f"{reg_in_cls_decl} {{\n"
        code += "switch (cls) {\n"
        for reg_class in self.hardware_regs:
            rc = HardwareRegister.get_func_name_of_class(reg_class, False)
            ec = HardwareRegister.get_enum_item_of_class(reg_class)
            code += f"case {ec}:\n"
            code += f"return {rc}(reg_num, get_alias, get_new, reg_num_is_enum);\n"
        code += "default:\n"
        code += "return NULL;\n"
        code += "}\n"
        code += "}\n\n"

        code += include_file("handwritten/hexagon_c/functions.c")

        self.write_src(code, path)

    def build_dwarf_reg_num_table(self, path: Path = Conf.get_path(OutputFile.HEXAGON_DWARF_REG_TABLE_H)):
        code = get_generation_warning_c_code()
        code += "\n"
        code += "static const char *map_dwarf_reg_to_hexagon_reg(ut32 reg_num) {"
        code += "\tswitch(reg_num) {"
        code += "\tdefault:\n"
        code += '\t\trz_warn_if_reached();\n\t\treturn "unsupported_reg";'
        dwarf_map = dict()
        hw: HardwareRegister
        for class_regs in self.hardware_regs.values():
            for hw in class_regs.values():
                if len(hw.dwarf_numbers) > 1:
                    # Alias register like P3:0 which combines all of them.
                    continue
                n = hw.dwarf_numbers[0]
                if n in dwarf_map:
                    # Always choose register with shorter name (no double regs)
                    if len(hw.asm_name) < len(dwarf_map[n].asm_name):
                        dwarf_map[n] = hw
                    continue
                dwarf_map[n] = hw

        sorted_dnums = {k: v for k, v in sorted(dwarf_map.items(), key=lambda item: item[0])}
        for num, hw in sorted_dnums.items():
            code += f'\tcase {num}: return "{hw.asm_name.upper()}";\n'
        code += "}}"
        self.write_src(code, path)

    def gen_resolve_reg_enum_id_fcn(self, param_name: str = "reg_num") -> str:
        var_name = param_name
        decl = "RZ_API ut32 hex_resolve_reg_enum_id(HexRegClass class, ut32 reg_num)"
        self.reg_resolve_decl.append(f"{decl};")

        code = f"{decl} {{\n" "\tswitch (class) {\n" "\tdefault:\n" f"\t\treturn {var_name};\n"
        for reg_class in self.hardware_regs:
            class_enum = HardwareRegister.get_enum_item_of_class(reg_class)
            parsing_code = HardwareRegister.get_parse_code_reg_bits(reg_class, var_name)
            if not parsing_code:
                continue
            code += f"\tcase {class_enum}:{{\n" f"{parsing_code}\n" f"\treturn {var_name};\n" "}"
        code += "}\n" "rz_warn_if_reached();\n" "return UT32_MAX;\n" "}"
        return code

    def gen_get_reg_name_fcns(self):
        code = ""
        reg_class: str
        for reg_class in self.hardware_regs:
            func_name = HardwareRegister.get_func_name_of_class(reg_class, False)
            function = f"\nconst char* {func_name}(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum)"
            self.reg_resolve_decl.append(function + ";")
            code += f"{function} {{"

            parsing_code = HardwareRegister.get_parse_code_reg_bits(reg_class, "reg_num")
            if parsing_code != "":
                code += f"reg_num = hex_resolve_reg_enum_id({HardwareRegister.get_enum_item_of_class(reg_class)}, reg_num);\n"

            warn_ior = "%s: Index out of range during register name lookup:  i = %d\\n"
            table_name = PluginInfo.REGISTER_LOOKUP_TABLE_NAME_V69.format(reg_class.lower())
            code += (
                f"if (reg_num >= ARRAY_LEN({table_name}))"
                f'{{RZ_LOG_INFO("{warn_ior}", "{func_name}", reg_num);'
                f'return NULL;}}'
            )
            code += f"const char *name;"
            code += f"const HexRegNames rn = {table_name}[reg_num];"
            code += "if (get_alias) {"
            code += "name = get_new ? rn.alias_tmp : rn.alias;"
            code += "} else {"
            code += "name = get_new ? rn.name_tmp : rn.name;}"

            warn_invalid_reg = "%s: No register name present at index: %d\\n"
            code += "if (!name) {" f'RZ_LOG_INFO("{warn_invalid_reg}", "{func_name}", reg_num);' 'return NULL;}'
            code += "return name;"
            code += "}\n"
        return code

    def build_asm_hexagon_c(self, path: Path = Conf.get_path(OutputFile.ASM_HEXAGON_C)) -> None:
        code = get_generation_warning_c_code()

        code += include_file("handwritten/asm_hexagon_c/include.c")
        code += include_file("handwritten/asm_hexagon_c/initialization.c")

        self.write_src(code, path)

    def build_hexagon_arch_c(self, path: Path = Conf.get_path(OutputFile.HEXAGON_ARCH_C)):
        code = get_generation_warning_c_code()

        code += include_file("handwritten/hexagon_arch_c/include.c")
        code += "\n"
        code += include_file("handwritten/hexagon_arch_c/functions.c")

        self.write_src(code, path)

    def build_hexagon_arch_h(self, path: Path = Conf.get_path(OutputFile.HEXAGON_ARCH_H)):
        code = get_generation_warning_c_code()
        code += get_include_guard("hexagon_arch.h")

        code += include_file("handwritten/hexagon_arch_h/includes.h")
        code += include_file("handwritten/hexagon_arch_h/typedefs.h")
        code += include_file("handwritten/hexagon_arch_h/declarations.h")
        code += "#endif"

        self.write_src(code, path)

    @staticmethod
    def copy_tests() -> None:
        with open("handwritten/analysis-tests/hexagon") as f:
            path = Conf.get_path(OutputFile.ANA_TESTS)
            Conf.check_path(path.absolute())
            with open(path, "w+") as g:
                set_pos_after_license(g)
                g.writelines(f.readlines())

        with open("handwritten/asm-tests/hexagon") as f:
            path = Conf.get_path(OutputFile.ASM_TESTS)
            Conf.check_path(path.absolute())
            with open(path, "w+") as g:
                set_pos_after_license(g)
                g.writelines(f.readlines())

        with open("handwritten/rzil-tests/hexagon") as f:
            path = Conf.get_path(OutputFile.RZIL_TESTS)
            Conf.check_path(path.absolute())
            with open(path, "w+") as g:
                set_pos_after_license(g)
                g.writelines(f.readlines())
        log("Copied test files to ./rizin/test/db/", LogLevel.DEBUG)

    def build_analysis_hexagon_c(self, path: Path = Conf.get_path(OutputFile.ANALYSIS_HEXAGON_C)) -> None:
        """Generates and writes the register profile.
        Note that some registers share the same offsets. R0 and R1:0 are both based at offset 0.
        """
        profile = self.get_alias_profile().splitlines(keepends=True)
        reg_offset = 0

        for hw_reg_class in self.hardware_regs:
            if hw_reg_class in [
                "IntRegsLow8",
                "GeneralSubRegs",
                "GeneralDoubleLow8Regs",
                "ModRegs",
            ]:
                continue  # Those registers would only be duplicates.

            hw_reg: HardwareRegister
            for hw_reg in {
                k: v for k, v in sorted(self.hardware_regs[hw_reg_class].items(), key=lambda item: item[1])
            }.values():
                profile.append(hw_reg.get_reg_profile(reg_offset, False) + "\n")
                reg_offset += 8 if (hw_reg.llvm_reg_class == "PredRegs") else hw_reg.size
                profile.append(hw_reg.get_reg_profile(reg_offset, True) + "\n")
                reg_offset += 8 if (hw_reg.llvm_reg_class == "PredRegs") else hw_reg.size
            profile.append("\n")
        profile[-1] = profile[-1][:-1] + ";\n"  # [:-1] to remove line break.

        code = get_generation_warning_c_code()

        code += include_file("handwritten/analysis_hexagon_c/include.c")
        code += "\n"
        code += include_file("handwritten/analysis_hexagon_c/functions.c")
        code += "\n"

        tmp = list()
        tmp.append("const char *p =")
        tmp += profile
        tmp = make_c_block(
            lines=tmp,
            begin="RZ_API char *get_reg_profile(RzAnalysis *analysis)",
            ret="return strdup(p);",
        )
        code += "\n" + "".join(tmp)

        code += "\n"
        code += include_file("handwritten/analysis_hexagon_c/initialization.c")

        self.write_src(code, path)

    def get_alias_profile(self) -> str:
        """Returns the alias profile of register. A0 = R0, SP = R29 PC = C9 etc."""
        indent = PluginInfo.LINE_INDENT

        p = "\n" + '"=PC{}C9\\n"'.format(indent) + "\n"
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

    @staticmethod
    def build_cc_hexagon_32_sdb_txt(path: Path = Conf.get_path(OutputFile.CC_HEXAGON_32_SDB_TXT)) -> None:
        """Builds the *incomplete* calling convention as sdb file.
        Hexagon can pass arguments and return values via different registers. E.g. either over R0 or R1:0.
        But the calling convention logic in rizin and the sdb is not sophisticated enough to model this.
        That is the reason we add only one of multiple possible argument/return register per db entry.
        """

        cc_dict = dict()
        Conf.check_path(path)
        with open(path, "w+") as f:
            for reg in HexagonArchInfo.CC_REGS["GPR_args"]:
                n = int(re.search(r"\d{1,2}", reg).group(0))
                if reg[0] == "R":
                    cc_dict[f"cc.hexagon.arg{n}"] = f"R{n}"
                elif reg[0] == "D":
                    # Rizin has currently no way to define a different CC for
                    # different sized parameters.
                    continue
                else:
                    raise ImplementationException(
                        f"Could not assign register {reg} to a specific return value."
                    )
            cc_dict["cc.hexagon.argn"] = "stack_rev"
            for reg in HexagonArchInfo.CC_REGS["GPR_ret"]:
                n = int(re.search(r"\d{1,2}", reg).group(0))
                if reg[0] == "R":
                    if HexagonArchInfo.CC_REGS["GPR_ret"].index(reg) == 0:
                        cc_dict["cc.hexagon.ret"] = f"R{n}"
                    else:
                        continue
                elif reg[0] == "D":
                    continue
                else:
                    raise ImplementationException(
                        f"Could not assign register {reg} to a specific return value."
                    )

            f.write("default.cc=hexagon\n\nhexagon=cc\ncc.hexagon.maxargs=6\n")
            for k, v in cc_dict.items():
                f.write(k + "=" + v + "\n")
            f.write("\nhvx=cc\ncc.hvx.name=hvx\ncc.hvx.maxargs=16\n")

            cc_dict = dict()
            for reg in HexagonArchInfo.CC_REGS["HVX_args"]:
                n = int(re.search(r"\d{1,2}", reg).group(0))
                if reg[0] == "V":
                    cc_dict[f"cc.hvx.arg{n}"] = f"V{n}"
                elif reg[0] == "W":
                    continue
                else:
                    raise ImplementationException(
                        f"Could not assign register {reg} to a specific return value."
                    )
            for reg in HexagonArchInfo.CC_REGS["HVX_ret"]:
                n = int(re.search(r"\d{1,2}", reg).group(0))
                if reg[0] == "V":
                    if HexagonArchInfo.CC_REGS["HVX_ret"].index(reg) == 0:
                        cc_dict["cc.hvx.ret"] = f"V{n}"
                    else:
                        continue
                elif reg[0] == "W":
                    continue
                else:
                    raise ImplementationException(
                        f"Could not assign register {reg} to a specific return value."
                    )
            for k, v in cc_dict.items():
                f.write(k + "=" + v + "\n")

    def apply_clang_format(self) -> None:
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
                    os.system(f"{self.config['CLANG_FORMAT_BIN']} -style file -i " + p)

    def write_src(self, code: str, path: Path) -> None:
        """Compares the given src code to the src code in the file at path and writes it if it differs.
        It ignores the leading license header and timestamps in the existing src file.
        Changes in formatting (anything which matches the regex '[[:blank:]]') are ignored as well.
        """

        if src_matches_old_src(code, path):
            self.unchanged_files.append(path)
            return
        Conf.check_path(path.absolute())
        with open(path.absolute(), "w+") as dest:
            log("Write {}".format(path), LogLevel.INFO)
            dest.writelines(code)
            self.edited_files.append(path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Import settings")
    parser.add_argument(
        "-j",
        action="store_true",
        default=False,
        help="Run llvm-tblgen to build a new Hexagon.json file from the LLVM definitions.",
        dest="bjs",
    )
    parser.add_argument(
        "--no-rzil",
        action="store_false",
        default=True,
        help="Do not invoke the RZIL compiler at all.",
        dest="rzil",
    )
    parser.add_argument(
        "--no-rzil-compile",
        action="store_false",
        default=True,
        help="(For testing only) Do not invoke the RZIL compiler to generate the instruction behavior. "
        'No "il_ops" files will be generated. Other IL code will.',
        dest="rzil_compile",
    )
    parser.add_argument(
        "--no-pcpp",
        action="store_true",
        default=False,
        help="Do not invoke the preprocessor of the RZIL compiler.",
        dest="skip_pcpp",
    )

    args = parser.parse_args()
    interface = LLVMImporter(args.bjs, args.rzil, args.skip_pcpp, args.rzil_compile)
