# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

import re

from bitarray import bitarray
from enum import IntEnum

from typing.io import TextIO

import PluginInfo
from UnexpectedException import UnexpectedException

try:
    from colorama import init, Fore, Style

    init()
    colorama_imported = True
except ImportError:
    print("colorama package not found. Enjoy your Script Noire :)")
    colorama_imported = False


class LogLevel(IntEnum):
    TODO = 0
    ERROR = 1
    WARNING = 2
    INFO = 3
    DEBUG = 4
    VERBOSE = 5


LOG_LEVEL = LogLevel.INFO


def log(msg: str, verbosity: LogLevel = LogLevel.INFO) -> None:
    """

    Args:
        msg: The message to log
        verbosity: msg level: error, log

    Returns: None

    """
    if verbosity > LOG_LEVEL:
        return

    if colorama_imported:
        if verbosity == LogLevel.ERROR:
            print(
                "["
                + Fore.RED
                + "X"
                + Style.RESET_ALL
                + "] {}".format(Fore.RED + msg + Style.RESET_ALL)
            )
        elif verbosity == LogLevel.WARNING:
            print(
                "["
                + Fore.LIGHTYELLOW_EX
                + "!"
                + Style.RESET_ALL
                + "] {}".format(Fore.LIGHTYELLOW_EX + msg + Style.RESET_ALL)
            )
        elif verbosity == LogLevel.INFO:
            print("[" + Fore.BLUE + "*" + Style.RESET_ALL + "] {}".format(msg))
        elif verbosity == LogLevel.DEBUG:
            print(
                "[" + Fore.LIGHTMAGENTA_EX + "#" + Style.RESET_ALL + "] {}".format(msg)
            )
        elif verbosity == LogLevel.VERBOSE:
            print("[" + Fore.LIGHTWHITE_EX + "-" + Style.RESET_ALL + "] {}".format(msg))
        elif verbosity == LogLevel.TODO:
            print("[" + Fore.GREEN + "T" + Style.RESET_ALL + "] {}".format(msg))

    else:
        if verbosity == LogLevel.ERROR:
            print("[X] {}".format(msg))
        elif verbosity == LogLevel.WARNING:
            print("[!] {}".format(msg))
        elif verbosity == LogLevel.INFO:
            print("[*] {}".format(msg))
        elif verbosity == LogLevel.DEBUG:
            print("[#] {}".format(msg))
        elif verbosity == LogLevel.VERBOSE:
            print("[-] {}".format(msg))
        elif verbosity == LogLevel.TODO:
            print("[T] {}".format(msg))


def standardize_syntax_objdump(syntax: str) -> str:
    """Change instruction syntax to match Qualcomm's objdump output.

    Args:
        syntax (str): instruction syntax, probably as was obtained from the parsed manual.

    Returns:
        str: matching objdump syntax (as close as possible).

    TODO:
        * Care should be taken not to modify the syntax patterns used in the decoder
            to recognize different attributes of the instruction, e.g., ``Rd`` can
            be split with a space like ``R d``.

        * Document the most complex regex.

    """

    # Add spaces to certain chars like '=' and '()'

    both_spaces = ["=", "+", "-", "*", "/", "&", "|", "<<", "^"]
    left_space = ["(", "!"]
    right_space = [")", ","]
    for c in both_spaces:
        syntax = syntax.replace(c, " " + c + " ")
    for c in left_space:
        syntax = syntax.replace(c, " " + c)
    for c in right_space:
        syntax = syntax.replace(c, c + " ")

    syntax = re.sub(r"\s{2,}", " ", syntax)

    # TODO: Special hack for the unary minus.
    syntax = re.sub(r"\#\s-\s", "#-", syntax)

    syntax = re.sub(r"\(\s*", "(", syntax)
    syntax = re.sub(r"\s*\)", ")", syntax)

    # Compound assignment
    syntax = re.sub(r"([\+\-\*\/\&\|\^\!]) =", r"\1=", syntax)

    syntax = syntax.replace(" ,", ",")
    syntax = syntax.replace(" .", ".")

    # Remove parenthesis from (!p0.new). just to match objdump,
    # but I prefer it with parenthesis.
    if ";" not in syntax:
        m = re.search(r"\( (\s* ! \s* [pP]\w(.new)? \s*) \)", syntax, re.X)

        if m:
            syntax = syntax.replace("(" + m.group(1) + ")", m.group(1))
            # syntax = re.sub(r'\( (\s* ! \s* [pP]\w(.new)? \s*) \)', r'\1', syntax, re.X)
            # TODO: The re.sub is not working, don't know why..

    syntax = syntax.replace("dfcmp", "cmp")
    syntax = syntax.replace("sfcmp", "cmp")

    # Special cases: ++, ==, !=
    syntax = syntax.replace("+ +", "++")
    syntax = syntax.replace("= =", "==")
    syntax = syntax.replace("! =", "!=")

    # Special cases: <<N, <<1, <<16, >>1
    syntax = syntax.replace(": << N", ":<<N")
    syntax = syntax.replace(": << 1", ":<<1")
    syntax = syntax.replace(": >> 1", ":>>1")

    syntax = syntax.strip()

    return syntax


def bitarray_to_uint(array: bitarray, endian: str = "little") -> int:
    if endian == "little":
        bits = array.to01()
        return int(bits[::-1], 2)
    elif endian == "big":
        return int(array.to01(), 2)
    else:
        raise UnexpectedException(
            "Endian can only be 'little' or 'big'. Was: {}".format(endian)
        )


def list_to_bitarray(bit_list: list, endian="little") -> bitarray:
    """Converts a list to the bitarray.
        The element at the list index 0 corresponds to the element at the lowest position/address.
        Example: [0, 0, 1] -> "001"
        The left most bit is at the lowest address.

    Args:
        bit_list: The list with bits set.
        endian: The endian of the list. [0, 0, 1] in little = 4 in big = 1

    Returns: For [0, 0, 1], endian=big: bitarray("001", big)

    """
    s = ""
    for bit in bit_list:
        s += str(bit)
    return bitarray(s, endian)


def list_to_int(bit_list: list, endian="little") -> int:
    ret = 0
    if endian == "big":
        for bit in bit_list:
            ret = (ret << 1) | bit
    else:
        for bit in bit_list[::-1]:
            ret = (ret << 1) | bit
    return ret


# TODO: support more syntax constructs
def make_c_block(
    lines: list, begin: str = "", end: str = "", ret: str = "", indent_depth: int = 1
) -> list:
    """
    Args: Creates a C code block with curly braces (useful for if/else or switch cases).
        lines: The lines of code.
        begin: The statement before the opening curly bracket.
        ret: The statement before the closing curly bracket.
        end: The statement after the closing curly bracket.
        indent_depth: The indention depth of the code block. If >1 the begin statement and all brackets will be indented
        as well.

    Returns: List with the formatted lines of code.
    """

    new = []
    indent: str = PluginInfo.LINE_INDENT * indent_depth
    p_ind: str = PluginInfo.LINE_INDENT * (indent_depth - 1)

    if begin != "":
        new += [p_ind + begin + " {\n"]
    else:
        new += ["{"]
    for line in lines:
        new += [indent + line]
    if ret != "":
        new += [indent + ret]
    if end != "":
        new += [p_ind + "} " + end]
    else:
        new += [p_ind + "}"]
    return new


def set_pos_after_license(file: TextIO) -> None:
    for line in file:
        if re.search(r"SPDX-License-Identifier", line):
            return
    file.seek(0, 0)
    return


def get_generation_warning_c_code() -> str:
    url = PluginInfo.REPO_URL
    msg = "{}\n".format(PluginInfo.GENERATION_WARNING_DELIMITER)
    msg += "// The following code is generated.\n"
    msg += "// Do not edit. Repository of code generator:\n"
    msg += "// {}\n".format(url)
    return msg


def get_license() -> str:
    lcs = "// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>\n"
    lcs += "// SPDX-License-Identifier: LGPL-3.0-only\n"
    return lcs


def indent_code_block(code: str, indent_depth: int) -> str:
    ret = ""
    indent: str = PluginInfo.LINE_INDENT
    for line in code.splitlines(keepends=True):
        ret += (indent * indent_depth) + line
    return ret


def unfold_llvm_sequence(sequence: str) -> list:
    """In the LLVM code generator one can define sequences of values.
    Here we build a given sequence and return the result as list.
    E.g.: (sequence "D%u", 0, 4) -> [D0, D1, D2, D3, D4]
    """

    s = re.search(r"\"(.+)\"", sequence).group(1)
    start = int(re.search(r", (\d*),", sequence).group(1))
    end = int(re.search(r", (\d*)\)", sequence).group(1))

    result = [re.sub(r"%[a-z]", str(x), s) for x in range(start, end + 1)]
    return result


def get_include_guard(filename: str) -> str:
    name = re.sub(r"\.", r"_", filename)
    name = name.upper()
    return "#ifndef {}\n#define {}\n".format(name, name)


def surround_with_include_guard(filename: str, lines: list) -> list:
    lines.insert(0, get_include_guard(filename))
    lines.append("\n\n#endif\n")
    return lines


def normalize_llvm_syntax(llvm_syntax: str) -> str:
    syntax = re.sub(r"#{0,2}\$", "", llvm_syntax)
    # Any number which stands before a register or immediate letter.
    syntax = re.sub(r"([A-Z][a-z,A-Z]+)[0-9]+", r"\1", syntax)
    # log("Normalized syntax: {} -> {}".format(llvm_syntax, syntax), LogLevel.DEBUG)
    return syntax
