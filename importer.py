#!/usr/bin/env python3
# pylint: disable=missing-docstring, invalid-name, line-too-long, too-many-lines, fixme
# pylint: disable=too-few-public-methods

from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

import argparse
import re
import operator
import collections
import sys

class UnexpectedException(Exception):
    def __init__(self, message):
        super().__init__(message)

def standarize_syntax_objdump(syntax):
    """Change instruction syntax to match Qualcomm's objdump output.

    Args:
        syntax (str): instruction syntax, probably as was obtained from the parsed manual.

    Returns:
        str: matching objdump syntax (as close as possible).

    TODO:
        * Care should be taken not to modify the syntax patterns used in the decoder
            to recognize different attributes of the instruction, e.g., ``Rd`` can
            be splitted with a space like ``R d``.

        * Document the most complex regex.

    """

    # Add spaces to certain chars like '=' and '()'

    both_spaces = ['=', '+', '-', '*', '/', '&', '|', '<<', '^']
    left_space = ['(', '!']
    rigth_space = [')', ',']
    for c in both_spaces:
        syntax = syntax.replace(c, ' ' + c + ' ')
    for c in left_space:
        syntax = syntax.replace(c, ' ' + c)
    for c in rigth_space:
        syntax = syntax.replace(c, c + ' ')

    syntax = re.sub(r'\s{2,}', ' ', syntax)

    # TODO: Special hack for the unary minus.
    syntax = re.sub(r'\#\s-\s', '#-', syntax)

    syntax = re.sub(r'\(\s*', '(', syntax)
    syntax = re.sub(r'\s*\)', ')', syntax)

    # Compound assingment
    syntax = re.sub(r'([\+\-\*\/\&\|\^\!]) =', r'\1=', syntax)

    syntax = syntax.replace(' ,', ',')
    syntax = syntax.replace(' .', '.')

    # Remove parenthesis from (!p0.new). just to match objdump,
    # but I prefer it with parenthesis.
    if ';' not in syntax:
        m = re.search(r'\( (\s* ! \s* [pP]\w(.new)? \s*) \)', syntax, re.X)

        if m:
            syntax = syntax.replace('(' + m.group(1) + ')', m.group(1))
            # syntax = re.sub(r'\( (\s* ! \s* [pP]\w(.new)? \s*) \)', r'\1', syntax, re.X)
            # TODO: The re.sub is not working, don't know why..


    syntax = syntax.replace('dfcmp', 'cmp')
    syntax = syntax.replace('sfcmp', 'cmp')

    # Special cases: ++, ==, !=
    syntax = syntax.replace('+ +', '++')
    syntax = syntax.replace('= =', '==')
    syntax = syntax.replace('! =', '!=')

    # Special cases: <<N, <<1, <<16, >>1
    syntax = syntax.replace(': << N', ':<<N')
    syntax = syntax.replace(': << 1', ':<<1')
    syntax = syntax.replace(': >> 1', ':>>1')

    syntax = syntax.strip()

    return syntax


class OperandTemplate():
    # TODO: Document class.

    __slots__ = ['syntax_name']
    # TODO: Change `syntax_name` to ``syntax``.

    def __init__(self, syntax_name):
        self.syntax_name = syntax_name


class RegisterTemplate(OperandTemplate):
    # TODO: Document class.

    __slots__ = ['is_register_pair', 'is_predicate', 'is_control', 'is_system', 'is_newvalue', 'syntax', 'index']

    def __init__(self, syntax_name):
        super(RegisterTemplate, self).__init__(syntax_name)
        self.syntax = syntax_name
        self.is_register_pair = False
        self.is_control = False
        self.is_system = False
        self.is_predicate = False
        self.is_newvalue = False
        self.index = 0

        # Register pair analysis.

        if self.syntax_name[0] == 'R':
            # General register.

            if len(self.syntax_name[1:]) == 2:
                self.is_register_pair = True

                if self.syntax_name[1] != self.syntax_name[2]:
                    # the two chars of the register pair do not match
                    raise UnexpectedException("The two chars of the register pair do not match:"
                                              "'{:s}' and '{:s}'".format(self.syntax_name[1], self.syntax_name[2]))

        if self.syntax_name[0] == 'P':
            # Predicate
            self.is_predicate = True

        if self.syntax_name[0] == 'C':
            # Control register
            self.is_control = True
            if len(self.syntax_name[1:]) == 2:
                self.is_register_pair = True

                if self.syntax_name[1] != self.syntax_name[2]:
                    # the two chars of the register pair do not match
                    raise UnexpectedException("The two chars of the register pair do not match:"
                                              "'{:s}' and '{:s}'".format(self.syntax_name[1], self.syntax_name[2]))

        if self.syntax_name[0] == 'S':
            # System control register
            self.is_system = True
            if len(self.syntax_name[1:]) == 2:
                self.is_register_pair = True

                if self.syntax_name[1] != self.syntax_name[2]:
                    # the two chars of the register pair do not match
                    raise UnexpectedException("The two chars of the register pair do not match:"
                                              "'{:s}' and '{:s}'".format(self.syntax_name[1], self.syntax_name[2]))


        if self.syntax_name[0] == 'N':
            # New value register
            self.is_newvalue = True


        # TODO: Check if the general purpose register is the only that uses reg. pairs.
        # (the control reg is also possible as reg. pair but they are usually rreferencedby their alias)



class ImmediateTemplate(OperandTemplate):
    # TODO: Document class. Develop the notion of immediate type, e.g., r, m, s, etc.

    __slots__ = ['scaled', 'type', 'syntax', 'signed', 'index']
    # TODO: Change `scaled` to ``scale`` (because it's used as an int, not a bool).

    def __init__(self, syntax_name, scaled=0):
        super(ImmediateTemplate, self).__init__(syntax_name)
        self.syntax = syntax_name
        self.scaled = scaled
        self.signed = False
        self.index = 0

        self.type = self.syntax_name[1].lower()
        if self.type == 's':
            self.signed = True

        if self.type not in ['s', 'u', 'm', 'r', 'g', 'n']:
            raise UnexpectedException("Unknown immediate type: {:s}".format(self.type))

class OptionalTemplate(OperandTemplate):
    __slots__ = ['syntax', 'index', 'syntax_pos']

    def __init__(self, syntax_name):
        super(OptionalTemplate, self).__init__(syntax_name)
        self.syntax = syntax_name
        self.index = 0
        self.syntax_pos = 0

class EncodingField():
    """Hexagon instruction encoding field, as seen in the manual.

    An encoding field can be characterized with only a mask (int) with the 1's set
    to indicate the positions of the field chars in the encoding. E.g., in the encoding
    (str) ``1011iiiiiiisssssPPiiiiiiiiiddddd``, the field ``s5`` would have a mask
    (int) like ``0b00000000000111110000000000000000``.

    This mask is used to later extract the value of the field in the instruction
    being disassembled, which would be used to generate either an immediate or
    register operand.

    This value extraction (bit by bit) can be time consuming. To improve performance,
    and taking advantage of the fact that most encoding fields are unified, (i.e.,
    all their field chars have consecutive order, like the example above), other
    (redundant) attributes are added to the class to reflect this.
    If a field is unified (``no_mask_split`` is True), the field value can
    be extracted just by applying a logical and operation, if the mask is split,
    after the logical and, the extracted bits need to be joined (which is time consumig
    for the disassembly process, as seen in the profiling results).

    Attributes:

        mask (int): resulting from setting to 1's the positions in the instruction encoding
            where the corresponding field char appears.
        mask_len (int): number of times the field char appears on the encoding field (i.e.,
            number of 1's in the mask).
        no_mask_split (bool): indicates whether all the field chars have a consecutive
            bit ordering (i.e., if all the 1's in the mask are together).
        mask_lower_pos (int): lowest bit index in the encoding where the field char is found
            (i.e. position of the first 1 in the mask).
        index (int): the number of operand

    TODOs:
        * Improve this class explanation, its use is in the disassembler, maybe move
            some of the explanation there (to `extract_and_join_mask_bits` function).

        * Clearly differentiate between bit-by-bit processing vs manipulating all
            bits together (extract bits).

        * Change `mask_lower_pos` to ``field_lower_pos`` or ``field_start_pos``.

        * Change `no_mask_split` to ``mask_split`` and adjust logic, asking
            for ``if not no_mask_split`` is too cumbersome.

    """
    __slots__ = ['mask', 'mask_len', 'no_mask_split', 'mask_lower_pos', 'index']

    def __init__(self):
        self.mask = 0
        self.mask_len = 0
        # Used to determine the sign of immediates.
        # TODO: Is mask_len used just for that?
        self.index = 0


class TemplateBranch():
    """Hexagon instruction branch.

    Attribute that adds information to the InstructionTemplate, used mainly
    in the IDA processor module to perform branch analysis..

    Attributes:

        type (str): of branch, useful for IDA analysis.
        target (OperandTemplate): operand template (register or immediate) in the instruction
            that contains the target of the branch.
        is_conditional (bool): True if conditional branch (there's an 'if' inside
            the syntax); False otherwise.

    TODOs:

        * Define the branch type inside a class or enum or somewhere unified,
            not as strings, and not inside the class.

        * Comment on each branch type separately, explaining the difference.

        * Change `all_branches` name to ``branch_syntax(es)``.

        * Change `all_branches` name to ``branch_syntax(es)``.

        * Document a branch as the union of hexagon jumps and calls.

        * The branch syntax is used like a regexp pattern, the spaces (added for readability)
            are ignored only if ``re.search`` is called with ``re.X`` argument
            (e.g., as `analyze_branch` does), enforce/specify this.

        * Once the branch types are unified give examples.

    """
    __slots__ = ['target', 'is_conditional', 'type']

    jump_reg_syntax = r'jumpr (?: :t | :nt)?'  # ``?:`` don't capture group
    jump_imm_syntax = jump_reg_syntax.replace('jumpr', 'jump')
    call_reg_syntax = r'callr'
    call_imm_syntax = call_reg_syntax.replace('callr', 'call')
    dealloc_ret_syntax = r'dealloc_return'
    all_branches = [jump_reg_syntax, jump_imm_syntax, call_reg_syntax, call_imm_syntax, dealloc_ret_syntax]

    def __init__(self, type):
        self.type = type
        self.target = None
        self.is_conditional = False

class TemplateToken():
    """Hexagon instruction template token.

    Used mainly in the IDA processor module, to print some parts of the syntax (tokens)
    in a special manner, matching the strings (`s`) with their corresponding operand (`op`).

    Attributes:

        s (str): token string.
        op (Optional[OperandTemplate]): operand template (if any) that corresponds to the token.

    TODOs:
        * Change `s` name to something more descriptive, maybe also `op`,
            using more than 2 letters is allowed...

    """
    __slots__ = ['s', 'op']

    def __init__(self, s):
        self.s = s
        self.op = None


class InstructionEncoding():
    """Hexagon instruction encoding.

    Attributes:
        text (str): encoding chars, without spaces, of len 32, each char represents one bit of the
            instruction, e.g., the encoding of ``Rd=add(Rs,#s16)`` is ``1011iiiiiiisssssPPiiiiiiiiiddddd``,
            ``text[0]`` corresponds to bit 31 and ``text[31]`` to bit 0 (LSB) of the encoding.
        mask (int): resulting from setting to 1's all the instruction defining bits, used in the
            disassembly to determine the type of an instruction.
        value (int): resulting from extracting only the instruction defining bits, used in conjunction with
            the mask to determine the type of an instruction.
        fields (Dict[str, EncodingField]): instruction encoding fields, indexed by the field char,
            e.g. fields['d'] -> EncodingField(Rd).

    TODOs:
        * Change `text` attribute's name, so as not to be confused with an instruction text.
        * Fields is a redundant attribute, because the encodings fields are contained
            in the operands dict. key (of the instruction template),
            but it's clearer this way. Should it be eliminated?

    """
    __slots__ = ['text', 'value', 'mask', 'fields']

    def __init__(self, text):

        #if len(text) != 32:
        #    raise UnexpectedException('There has been a problem during the instruction definition import process.')

        # TODO: Check also `text` for spaces.

        # TODO: check that ICLASS bits (31:28 and 31:29,13 for duplex) in `text` are always defined to 0/1.

        self.text = text

        self.fields = {}

        self.generate_mask_and_value()
        self.generate_fields()

    def generate_mask_and_value(self):
        """Generate the mask and value of the instruction encoding, from its text (str).

        There are no Args nor Return values, everything is done manipulating the
        object attributes: the input would be `self.text` and the output `self.mask`
        and `self.value`.

        """
        self.mask = 0
        self.value = 0

        for text_pos in range(32):

            mask_pos = 31 - text_pos
            # The orders of mask bits (int) and text bits (str) are reversed.

            if self.text[text_pos] in ['0', '1']:
                self.mask |= (1 << mask_pos)
                self.value |= int(self.text[text_pos]) << mask_pos

    def generate_fields(self):
        """Generate instruction fields of the instruction encoding, from its text (str).

        Parse everything else that's not a instruction defining bit (0/1), like the ICLASS
        bits, and generate the corresponding fields from each different spotted char.
        The other type of chars ignored (besides 0/1) are '-' (irrelevant bit)
        and 'P' (parse bit).

        The fields created (EncodingField) do not differentiate between immediate or register,
        they are just a bit field at this stage.

        The generation of each field mask is pretty straight forward, but the process
        has been complicated with the fact that the generated mask is checked to see if
        bits are consecutive (no_mask_split), for performance reasons. See `EncodingField`
        description.

        There are no Args nor Return values, everything is done manipulating the
        object attributes: the input would be `self.text` and the output `self.fields`.

        TODOs:
            * Rethink this explanation. 'P' is a valid field, but I'm skipping it because it
                won't be a valid imm. o reg. operand. So even though this encoding fields
                are just bits their ultimate use will be for operands.

            * Use the terms "specific fields" (from "Instruction-specific fields") and
                Common fields (defined in section 10.2 of the manual). ICLASS and parse
                bits (common fields) are the ones I'm ignoring.

            * The rationale behind the `no_mask_split` is split between here and
                `EncodingField`. Unifiy.

            * Avoid skipping any field here, create all the bit fields from the instruction,
                and then skip them during reg./imm. ops. creation, to simplify the logic
                here (less coupling, this function is doing -or knowing- more than it should).

        """
        field_last_seen_pos = {} # type: Dict[str, int])
        # Used to detect a mask split.
        # TODO: Elaborate on this.

        # TODO: XXX: add the index of operand for each field
        for text_pos in range(32):

            mask_pos = 31 - text_pos
            # The orders of mask bits (int) and text bits (str) are reversed.

            if mask_pos in [14, 15]: # skip 'P', parse bits
                continue
                # TODO: Remove this check when this function is permitted to parse all fields
                # (and discard the P field later when generating the operands).

            c = self.text[text_pos]

            if c not in ['0', '1', '-']:
                # TODO: Change to a continue clause, to remove all the following indentation.

                if c not in self.fields:
                    # Char seen for the first time, create a new field.

                    self.fields[c] = EncodingField()
                    self.fields[c].no_mask_split = True
                    field_last_seen_pos[c] = (-1)
                    # (-1): used to indicate that it's a new field, and there's
                    # no last seen char before this one.

                self.fields[c].mask |= (1 << mask_pos)
                self.fields[c].mask_len += 1

                # Detect a split in the field (and if so, reflect it on the mask).

                if field_last_seen_pos[c] != -1:
                    if mask_pos != (field_last_seen_pos[c] - 1): # mask_pos iteration is going ackwards
                        self.fields[c].no_mask_split = False

                field_last_seen_pos[c] = mask_pos

        for c in self.fields:
            self.fields[c].mask_lower_pos = field_last_seen_pos[c]
            # The last seen position in the text (str) of each field is the
            # lowest position in the mask (int), as their orders are reversed.


class InstructionDefinition():
    """Definition of an instruction (like the manual): syntax, encoding, and beahvior.

    Instructions obtained by the importer (either from the manual or the objdump
    headers). It has the minimal processing, only on the instruction encoding, converted
    to `InstructionEncoding` (it has no use as a string), the major work is done in
    the `InstructionTemplate` through the decoder.

    The behavior attribute is optional, because the parser still doesn't support many of
    the manual's behavior strings.

    Attributes:
        syntax (str)
        encoding (InstructionEncoding)
        behavior (str)

    """
    __slots__ = ['syntax', 'encoding', 'behavior']

    def __init__(self, syntax, encoding, behavior):
        self.syntax = syntax
        self.encoding = InstructionEncoding(encoding)
        self.behavior = behavior

# TODO: Handle also TAB characters

class InstructionTemplate():
    """Definition of the instruction with the maximum processing done before being used for disassembly.

    Created by the decoder from an `InstructionDefinition`.
    All the major attributes of the instruction are processed and
    stored here, e.g., operands, duplex, branches, tokens, etc.

    Attributes:
        encoding (InstructionEncoding): Hexagon instruction encoding, as seen in the manual.
        syntax (str): Hexagon instruction syntax, as seen in the manual, e.g. ``Rd=add(Rs,#s16)``.
        operands (Dict[str, InstructionOperand]): Operands (registers or immediates) indexed by their
            respective field char, e.g., operands['d'] -> InstructionOperand(Rd).
        mult_inst (bool): Has more than one atomic instruction, i.e., has a ';' in the syntax.
        is_duplex (bool): Indicates if this is a duplex instruction.
        imm_ops (List[ImmediateTemplate]): List of the instruction register operand templates.
        reg_ops (List[RegisterTemplate]): List of the instruction immediate operand templates.
        opt_ops (List[OptionalTemplate]): List of the instruction optional operand templates.
        branch (Optional[TemplateBranch]): If not None, has the branch being performed by the
            instruction, identified by the encoding analyzing the instruction syntax and not
            its behavior (as it should).
        behavior (str): Hexagon instruction behavior, as seen in the manual, e.g. ``Rd=Rs+#s;``.
        imm_ext_op (Optional[ImmediateTemplate]): "Pointer" to the immediate operand that can
            be extended in the instruction. It is just a hint for the disassembler, to let it
            know what immediate operand can be the target of a constant extension. "Pointer"
            here means that it has one of the imm. ops. in the `imm_ops` list.
        tokens (List[TemplateToken]): List of strings representing the tokenized behavior, where
            splits are done in the cases where part of the syntax can be linked to an operand,
            see `HexagonInstructionDecoder.tokenize_syntax`.
        name (str): Name.

    """
    __slots__ = ['encoding', 'syntax', 'operands', 'mult_inst',
                 'is_duplex', 'imm_ops', 'reg_ops', 'opt_ops', 'branch', 'behavior',
                 'imm_ext_op', 'tokens', 'name']


    register_operand_field_chars = ['t', 'd', 'x', 'u', 'e', 'y', 'v', 's']
    # Seen on the manual

    # Added from the objdump headers, but not in the manual
    register_operand_field_chars.extend(['f', 'z'])

    immediate_operand_field_chars = ['i', 'I']

    other_field_chars = ['-', 'P', 'E', 'N']
    # 'E' added from the objdump header encodings (not in the manual)

    field_chars = register_operand_field_chars + \
                  immediate_operand_field_chars + \
                  other_field_chars
    # TODO: move all field char definitions inside `generate_operand` or in `common.py`.

    def __init__(self, inst_def):

        #print(inst_def)
        #if not isinstance(inst_def, InstructionTemplate):
        #    pass

        self.encoding = inst_def.encoding
        self.syntax = standarize_syntax_objdump(inst_def.syntax)
        self.behavior = inst_def.behavior
        # TODO: Create an ``InstructionField`` that groups these 3 attributes.

        self.imm_ops = []
        self.reg_ops = []
        self.opt_ops = []

        self.operands = {}
        # Contains the same info as imm_ops + reg_ops, only used inside
        # `generate_instruction_operands`.
        # TODO: Remove this attribute.

        self.branch = None
        self.imm_ext_op = None
        self.tokens = []
        self.name = None

        self.mult_inst = (';' in self.syntax)

        self.is_duplex = (self.encoding.text[16:18] == '00')
        # PP (parity bits) set to '00'
        #print("is duplex? {0}".format(self.is_duplex))

        for c in self.encoding.fields:
            #print(c)
            self.generate_operand(c)

        # Calculate operand indexes
        self.operand_calculate_indices()

    # C: char, ie: inst encoding
    def generate_operand(self, c):
        """Generate an operand from an instruction field.

        Args:
            c (str): Field char.

        Returns:
            None: the information is added to `reg_ops`/`imm_ops` and `operands`
                of the same InstructionTemplate.

        """
        #print("syntax = \"{0}\" char = \"{1}\"".format(self.syntax, c))
        if c not in InstructionTemplate.field_chars:
            print("Field char {:s} not recognized.".format(c))
            raise UnexpectedException("Field char {:s} not recognized.".format(c))

        if c in self.register_operand_field_chars:
            reg = self.match_register_in_syntax(self.syntax, c)
            if reg:
                self.operands[c] = reg
                self.reg_ops.append(reg)
                return
            print("not register operand match in syntax! [{0:s}]".format(c))

        if c in self.immediate_operand_field_chars:
            imm = self.match_immediate_char_in_syntax(self.syntax, c)
            if imm:
                self.operands[c] = imm
                self.imm_ops.append(imm)

                return
            print("no immediate operand match in syntax! [{0:s}]".format(c))

        # There is a pretty similar structure in both processings.
        # TODO: Can this be abstracted to a more general function?
        if c == 'N':
            # 'N' operand, it indicates an optional behavior in the instruction (which doesn't happen often).
            m = re.search(r"(\[\s*:\s*<<\s*N\s*\])", self.syntax)
            if m:
                opt = OptionalTemplate('[:<<N]')
                self.operands[c] = opt
                self.operands[c].syntax_pos = (m.start(1), m.end(1))
                self.opt_ops.append(opt)
                return
            print("no optional operand match in syntax!")

        # If it gets here there's an unforeseen field char that was not processed correctly.
        print("Field char {:s} not processed correctly.".format(c))

        raise UnexpectedException("Field char {:s} not processed correctly.".format(c))

    def match_register_in_syntax(self, syntax, reg_char):
        """Find a register operand in the syntax with a specified field char.

        Args:
            syntax (str): Instruction syntax.
            reg_char (str): Field char (str of len 1) used in the instruction encoding to
                represent a field that holds the value for a register operand.

        Returns:
            Optional[RegisterTemplate]: if found, None otherwise.

        TODO:
            * Check other possible registers, Mx for example.

        """

        # Match registers, first generic ones (Rx), then predicates (Px)

        reg_templates = [
            r"(R" + reg_char + r"{1,2})",
            # {1,2}: it can be a double register (e.g. Rdd).

            r"(P" + reg_char + r")",
            r"(N" + reg_char + r".new)",
            r"(M" + reg_char + r")",
            r"(C" + reg_char + r")",

            # Added from the objdump headers, but not in the manual.
            r"(G" + reg_char + r")",
            r"(S" + reg_char + r"{1,2})", # Can be double register too
        ]

        for rt in reg_templates: # type: str

            m = re.search(rt, syntax)

            if m:
                return RegisterTemplate(m.group(1))

        return None

    def match_immediate_char_in_syntax(self, syntax, imm_char):
        """Find an immediate operand in the syntax with a specified field char.

        Args:
            syntax (str): Instruction syntax.
            imm_char (str): Field char (str of len 1) used in the instruction encoding to
                represent a field that holds the value for an immediate operand.

        Returns:
            Optional[ImmediateTemplate]: if found, None otherwise.

        """
        if imm_char == 'i':
            imm_chars = ['u', 's', 'm', 'r', 'g']

        elif imm_char == 'I':
            imm_chars = ['U', 'S', 'M', 'R', 'G']
            # TODO: Use list comprehensions.
        else:
            raise UnexpectedException("Unexpected syntax specifier")

        for ic in imm_chars: # type: str

            m = re.search(r"(#" + ic + r"\d{1,2})" + r"(:\d)?", syntax)
            # E.g., ``#s16:2``, the optional ``:2`` indicates a scaled immediate.
            # E.g., ``#g16:0`` indicates GP-relative offset
            # TODO: Improve readabilty of this regex.

            if m:
                imm_syntax = m.group(1)
                scale_factor = 0

                if m.group(2):
                    imm_syntax += m.group(2)
                    scale_factor = int(m.group(2)[1])
                    # ``[1]``: used to skip the ':' in the syntax.

                return ImmediateTemplate(imm_syntax, scale_factor)

        return None

    def operand_calculate_indices(self):
        pos = {}
        i = ic = rc = oc = 0
        for k,v in self.operands.items():
            pos[k] = self.syntax.find(v.syntax)
        sortedpos = sorted(pos.items(), key=operator.itemgetter(1))

        for c,p in sortedpos:
            self.operands[c].index = i
            # Update imm_ops and reg_ops order too. They were added to imm_ops/reg_ops in
            # encoding order, not in syntax order (by generate_operands()) this broke at least
            # two instructions.
            #
            # Syntax-order:     Rd = mux(Pu, #s8, #S8)
            #                   Order: [d, u, s, S]; Reg. order: [d, u]; Imm. order: [s, S]
            #
            # Encoding-order:   0111101uuIIIIIIIPPIiiiiiiiiddddd
            #                   Order: [u, I, i, d]; reg. order: [u, d]; imm. order: [I, i]
            #                   (I = S, s = i etc.)

            if isinstance(self.operands[c], ImmediateTemplate):
                self.imm_ops[ic] = self.operands[c]
                ic += 1
            elif isinstance(self.operands[c], RegisterTemplate):
                self.reg_ops[rc] = self.operands[c]
                rc += 1
            elif isinstance(self.operands[c], OptionalTemplate):
                self.opt_ops[oc] = self.operands[c]
                oc += 1
            else:
                print("Operand template: {}".format(self.operands[c]))
                raise UnexpextectedException("Unknow operands template")

            i += 1

class HexagonInstructionDecoder():
    """Hexagon instruction decoder.

    Takes instruction definitions and process them to instruction templates.

    Attributes:
        inst_def_list (List[InstructionDefintion]): List of instruction definitions saved during the parsing stage.
        inst_template_list (List[InstructionTemplate]): List of instruction definitions templates generated
            by the decoder from the list of definitions.

    """
    __slots__ = ['inst_def_list', 'inst_template_list']

    def __init__(self, inst_def_list):
        """Load the instruction definitions and convert it to instruction templates.

        Creates the InstructionTemplate and processes it.

        TODOs:
            * All the calls in the loop could be done inside the InstructionTemplate
                constructor, should it?

        """
        self.inst_def_list = inst_def_list
        self.inst_template_list = [InstructionTemplate(inst_def) for inst_def in self.inst_def_list]

        for template in self.inst_template_list:
            self.analyze_branch(template)
            self.resolve_constant_extender(template)
            self.tokenize_syntax(template)

    def tokenize_syntax(self, template):
        """Generate a list of tokens from the instruction syntax.

        Takes the syntax string and split it in smaller strings (tokens). The split is
        done to generate a link between the instruction operands and the substrings
        that correspond to it, e.g., ``Rd=add(Rs,#s16)`` would be splitted like:
        ``['Rd', '=add(', 'Rs', ',', '#s16', ')']`` to isolate the three operand strings
        (registers ``Rd``, ``Rs`` and immediate ``#s16``) from the rest of the
        syntax string.

        The substrings are later used to generate TemplateToken objects, which are composed
        of a string with its associated operand (if it exists).

        Args:
            template (InstructionTemplate): to be processed.

        Returns:
            None: the data is applied to the template itself.

        TODOs:
            * Should the 2 steps (split and match) be done together?

        """
        tokens = [template.syntax] # type: List[str]
        # The syntax will be splitted to this list of strings that will be later
        # used to create the template tokens.
        for op in template.reg_ops + template.imm_ops + template.opt_ops:  # type: InstructionOperand

            new_tokens = [] # type: List[str]
            # New tokens generated from the current tokens, updated at the end of the loop.
            # HACK: mask the '[' and ']' characters
            reop = op.syntax_name.replace('[', '\[')
            for str_token in tokens:
                new_tokens.extend(
                    re.split('(' + reop + ')', str_token)
                )
                # If a operand is found in the current token, split it to isolate
                # the operand, re.split is used because, unlike string.split, it doesn't
                # discard the separator (the operator name in this case) when enclosed
                # in parenthesis.
            if len(new_tokens) != len(tokens) + 2 * template.syntax.count(op.syntax_name):
                raise UnexpectedException("Tokens count doesn't match the syntax")
                # Every split (appearance of the operand in the syntax)
                # has to generate 2 new tokens (an old token is split into 3,
                # the separator and left/right tokens, that are always generated
                # even if they are empty strings).

            tokens = new_tokens
            # TODO: use list comprehensions and eliminate `new_tokens`.

        # Discard possibly empty generated strings.
        tokens = list(filter(lambda s: len(s) > 0, tokens))

        # Generate list of TemplateToken and match string tokens to operands.

        for str_token in tokens:

            #template_token = TemplateToken(str_token.lower())
            template_token = TemplateToken(str_token)
            # TODO: Is it ok to convert to lowercase here?
            # The letter case of the operands text is useful (specially in IDA) to
            # identify them quickly in the visual analysis (from the rest of the instruction).

            for op in template.reg_ops + template.imm_ops + template.opt_ops: # type: InstructionOperand

                if str_token == op.syntax_name:
                    # The string token names the operand, match them.

                    template_token.op = op
                    break

            template.tokens.append(template_token)

        return

    def resolve_constant_extender(self, template):
        """In case there are two imm. operands, indicate to which one would apply a constant extension.

        This is done for instructions that can be extended by a constant but have two
        immediate operands and it has to be indicated to which one the extension applies.

        The function ``apply_extension()`` in instruction behaviours is used as an indication
        that a constant extension can be applied, and the argument of the function specifies
        the syntax of which immediate operand it applies to.

        Args:
            template (InstructionTemplate): to be processed.

        Returns:
            None: the data is applied to the template itself.

        TODOs:
            * Add to the function description an example of an instruction where
                there are two imm. ops. and the ``apply_extension()`` resolves which one.

        """
        if len(template.imm_ops) < 2:
            # There's no need to perform the check, there's (at most) only one
            # immediate operand to choose from.
            if template.imm_ops:
                template.imm_ext_op = template.imm_ops[0]
            return
        m = re.search(r"""
            # Looking for something like: "apply_extension(...);"

            apply_extension
            \(
                (.*?)           # Capture group for the imm. op. name, e.g., ``#s``.
            \)
        """, template.behavior.replace(' ', ''), re.X)
        # The spaces are removed from the behavior string to simplify the regex.

        if m is None:
            # No constant extension found in the behavior.
            # But it has immediates -> assume imm_ops[0]
            template.imm_ext_op = template.imm_ops[0]
            return

        imm_op_ext_name = m.group(1)
        # Name of the imm. op. that is the argument of ``apply_extension()``.

        for imm_op in template.imm_ops:
            if imm_op_ext_name in imm_op.syntax_name:
                # An equal comparison is not made in the previous if because
                # the op. name in the apply_extension argument is usually a shorter
                # version of the name in the syntax (normally because the
                # operand's bit size was removed), e.g., ``#s16`` in
                # ``Rd=add(Rs,#s16)`` is referenced as ``apply_extension(#s);``.
                template.imm_ext_op = imm_op
                return

        raise UnexpectedException("Cannot parse constant extender")
        # If the regex matched, the operand should have been found in the previous loop.

    def analyze_branch(self, template):
        """Find a branch in the instruction syntax and generate the template info.

        Used in (IDA) static analysis.

        Args:
            template (InstructionTemplate): to be processed.

        Returns:
            None: the data is applied to the template itself.

        TODOs:
            * Change function name to something like 'find_branch(es)'.

            * This type of analysis should be done by studying the REIL translation
                of the instruction, which truly reflects its behaviour. When the REIL
                translation is added this function should be adapted.

            * Multiple branches in one instruction: is it possible? I think not,
                at most, two branches in one packet but separate. Check this.

            * The branch string itself is used to represent it, maybe some constants
                should be used instead.

        """
        for branch_syntax in TemplateBranch.all_branches: # type: str
            # Find any of the possible branch syntaxes in the instruction
            # to detect a branch.
            m = re.search(branch_syntax, template.syntax, re.X)
            if m is None:
                continue

            if branch_syntax == TemplateBranch.dealloc_ret_syntax:
                # The instruction is a 'dealloc_return', a jump to the
                # LR as target.
                pass

            template.branch = TemplateBranch(branch_syntax)

            template.branch.is_conditional = ('if' in template.syntax)
            # TODO: The if could be applying to another sub-instruction. Improve detection.

            if branch_syntax in [TemplateBranch.jump_reg_syntax, TemplateBranch.call_reg_syntax]:
                # Branch type: jump/call register.

                # Find which register is the target of the branch.

                for reg in template.reg_ops: # type: RegisterTemplate
                    m = re.search(branch_syntax + r'\s*' + reg.syntax_name, template.syntax, re.X)
                    if m:
                        template.branch.target = reg
                        return

                # The target register operand was not found, this shouldn't happen, but
                # for now the case of register alias (specially the case of LR) is not
                # being handled, so an exception can't be raised, and this case is
                # tolerated (retuning instead).

                # raise UnexpectedException()
                return

            if branch_syntax in [TemplateBranch.jump_imm_syntax, TemplateBranch.call_imm_syntax]:
                # Branch type: jump/call immediate.

                for imm in template.imm_ops: # type: ImmediateTemplate
                    m = re.search(branch_syntax + r'\s*' + imm.syntax_name.replace('#', r'\#'), template.syntax, re.X)
                    # The '#' (used in imm. op. names) is escaped, as it is interpreted as
                    # a comment in verbose regex (re.X), and verbose regex is used because
                    # the branch syntax is written with spaces (verbose style) to improve
                    # its readability.

                    if m:
                        template.branch.target = imm
                        return

                raise UnexpectedException("Cannot find target immediate operand")
                # The target immediate operand should have been found.

        return

class ManualParser:

    def __init__(self, manual_fn):
        self.manual = open(manual_fn, 'r', newline=None) # universal newlines, to get rid of '\r' when opening in linux
        self.lines = self.manual.read().splitlines()
        self.ln = 0
        self.current_line = self.lines[self.ln]

        # TODO: change the name, this are not yet instruction templates until the decoder process them
        self.instructions = []

        self.syntax_behavior_text = []


        self.current_inst_name = ""
        self.total_encodings = 0

    def get_next_line(self):
        self.ln += 1

        if self.ln == len(self.lines):
            raise self.OutOfLinesException()

        return self.get_current_line()

    def peek_next_line(self):
        if self.ln + 1 == len(self.lines):
            raise self.OutOfLinesException()

        return self.lines[self.ln + 1]

    def peek_prev_line(self):
        if self.ln - 1 == -1:
            raise self.OutOfLinesException()

        return self.lines[self.ln - 1]

    def get_current_line(self):
        self.current_line = self.lines[self.ln]
        return self.current_line

    def get_prev_line(self):
        self.ln -= 1

        if self.ln < 0:
            raise self.UnexpectedException()

        return self.get_current_line()

    def go_to_instruction_set_start(self):

        try:
            while True:
                m = re.search(r"Hexagon V62 Programmer's Reference Manual\s*Instruction Set", self.current_line)
                if m:
                    #print("Found start of Instruction Set at line: " + str(self.ln))
                    #print(self.current_line)
                    break

                self.get_next_line()

        except self.OutOfLinesException:
            raise self.UnexpectedException()

    def find_encondings(self):
        try:
            inside_encoding = False
            inside_behavior = False

            last_syntax_found_ln = -1
            last_behavior_found_ln = -1
            while True:

                self.get_next_line()
                #print(self.current_line)

                m = re.search(r"\s*Syntax\s*Behavior\s*", self.current_line)
                if m:
                    #print("\nFound start of Syntax/Behavior at line: " + str(self.ln))
                    #print(self.current_line)
                    inside_behavior = True
                    continue

                m = re.search(r"^\s*Class: .*", self.current_line)
                if m:
                    #print("\nFound start of Class at line: " + str(self.ln))
                    #print(self.current_line)
                    inside_behavior = False
                    continue

                m = re.search(r"\s*Encoding\s*", self.current_line)
                if m:
                    #print("\nFound start of Encoding at line: " + str(self.ln))
                    #print(self.current_line)
                    inside_encoding = True
                    inside_behavior = False
                    continue

                # The end of an econding section is typically signaled by the start of the "Field name" section.
                m = re.search(r"Field name\s*Description", self.current_line)
                if m:
                    #print("Found end of Encoding at line: " + str(self.ln) + '\n')
                    #print(self.current_line)
                    inside_encoding = False
                    inside_behavior = False
                    continue

                '''
                Syntax/Behavior extraction:
                Organized in two columns.
                '''
                if inside_behavior:


                    # Instructions without a clear separation of syntax and behavior are skipped
                    complicated_instructions = [
                        "Vector",
                        "Floating",
                        "Complex add/sub halfwords",
                        "Multiply",
                        "Shift by register",
                        "Set/clear/toggle bit",
                        "Extract bitfield",
                        "Test bit",
                        "CABAC decode bin",
                    ]
                    if True in [ci.lower() in self.current_inst_name.lower() for ci in complicated_instructions]:
                        continue


                    #if self.current_line.strip().decode('utf-8') == '':
                    if self.current_line.strip() == '':
                            continue

                    # Page header/footer skip
                    # TODO: maybe this should apply to more parts of the code, no just syntax/behavior
                    if ("Hexagon V62 Programmer's Reference Manual" in self.current_line or
                        "MAY CONTAIN U.S. AND INTERNATIONAL EXPORT" in self.current_line or
                        "80-N2040-36 B" in self.current_line):
                        continue




                    # Try to match the 2 column format, basically tryng to see the separation space between them (the 5 spaces min requirement)
                    m = re.search(r"^\s*(\S.+?\S)\s{5,}(\S.+)", self.current_line)
                    if m:
                        #print("Found pair of syntax/behavior")
                        #print("Group 1: " + m.group(1))
                        #print("Group 2: " + m.group(2))
                        behavior_1st_column_pos = m.start(1)
                        behavior_2nd_column_pos = m.start(2)

#                         if self.current_line[0:behavior_2nd_column_pos].strip() != '':
#                             # Syntax column
#                             # TODO this if check should be include in the previous regex

                        # Continuation syntax (in 2 consecutive lines)
                        if self.ln - 1 == last_syntax_found_ln:
                            #print("Cont Syntax: " + m.group(1))
                            self.syntax_behavior_text[-1][0] += " " + m.group(1)
                        else:
                            #print("New Syntax: " + m.group(1))
                            self.syntax_behavior_text.append([m.group(1), ''])
                        last_syntax_found_ln = self.ln

                        #print("Behavior is: " + m.group(2))
                        self.syntax_behavior_text[-1][1] += m.group(2)
                        last_behavior_found_ln = self.ln

                    else:
                        # Can be a behavior continuation line
                        if self.current_line[behavior_2nd_column_pos:].strip() != '':
                            if self.ln - 1 == last_behavior_found_ln:
                                #print("Behavior cont is: " + self.current_line[behavior_2nd_column_pos:].strip())
                                self.syntax_behavior_text[-1][1] += self.current_line[behavior_2nd_column_pos:].strip()
                                last_behavior_found_ln = self.ln


                '''
                Start of a page of the "Instruction Set" section: if the first non empty line that appears
                in the next 3 to 5 lines (usually its 3 blank lines and the title)
                has text at the begining of the line, it's likely a new title, and hence a new instruction
                name. I'm assuming the title has at least 3 chars.

                TODO: Double line titles
                '''
                m = re.search(r"Hexagon V62 Programmer's Reference Manual\s*Instruction Set", self.current_line)
                if m:
#                     print "Found start of Instruction Set page at line: " + str(self.ln)
                    start_ln = self.ln
                    title_found = False
                    for _ in range(5):
                        self.get_next_line()
#                         print self.current_line
                        m = re.search(r"^\w{3}", self.current_line)
                        if m:
                            #print("Found title at line: " + str(self.ln))
                            #print(self.current_line)
                            self.current_inst_name = self.current_line.strip()
                            break

                    # Just to be sure I return to where the search for a title began
                    if not title_found:
                        self.ln = start_ln

                    continue

                # The first four bits (ICLASS) of an encoding are always set (either to 0 or 1),
                # and are at the start of the line
                m = re.search(r"^([01]\s*){4}", self.current_line)
                if m:
#                     print "Found encoding at line: " + str(self.ln)
#                     print self.current_line

                    # Bits not defined in the encoding are marked as "-", not left blank,
                    # so there is always 32 non-whites, particulary: 0/1, chars or "-".
                    m = re.search(r"^(([01a-zA-Z\-]\s*){32})(.*)$", self.current_line)
                    if m is None:
                        raise self.UnexpectedException()

                    ie = m.group(1).replace(' ', '')
                    syntax = m.group(3) # My limited regex understanding doesn't get why this is the 3rd group and not the 2nd, but this works.

                    # The syntax may be splitted in 2 lines, in this case the second line
                    # is all white spaces, until the position where the syntax started in the
                    # previous line, where the sytax string continues. Or can be the contrary,
                    # the second line of the syntax has the encoding and the first line is blank
                    next_line = self.peek_next_line()
                    prev_line = self.peek_prev_line()

                    if len(next_line) > m.start(3) and re.search(r"^\s*$", next_line[0 : m.start(3)]): # all spaces up to the syntax string
                        # TODO: Change name m2.
                        m2 = re.search(r"^(\S.*)", next_line[m.start(3):]) # here has to be something (I can't specify what exactly besides a non space)
                        if m2:
                            #print("Found syntax continuation")
                            #print(("1st line: {:s}".format(syntax)))
                            #print(("2nd line: {:s}".format(m2.group(1))))

                            syntax += ' ' + m2.group(1)

                            self.get_next_line() # To really pass over this continuation syntax line

                    elif len(prev_line) > m.start(3) and re.search(r"^\s*$", prev_line[0 : m.start(3)]):
                        # TODO: Change name m2.
                        m2 = re.search(r"^(\S.*)", prev_line[m.start(3):]) # here has to be something (I can't specify what exactly besides a non space)
                        if m2:
                            #print("Found syntax continuation in prev line")
                            #print(("1st line: {:s}".format(m2.group(1))))
                            #print(("2nd line: {:s}".format(syntax)))

                            syntax = m2.group(1) + ' ' + syntax

                    else:
                        # TODO: Tidy up.
                        # The same can happen but with a disalignment of the other syntax line (prev or next) by 1 char
                        if len(next_line) > (m.start(3) - 1) and re.search(r"^\s*$", next_line[0 : (m.start(3) - 1)]): # all spaces up to the syntax string
                            # TODO: Change name m2.
                            m2 = re.search(r"^(\S.*)", next_line[(m.start(3) - 1):]) # here has to be something (I can't specify what exactly besides a non space)
                            if m2:
                                #print("Found syntax continuation")
                                #print(("1st line: {:s}".format(syntax)))
                                #print(("2nd line: {:s}".format(m2.group(1))))

                                syntax += ' ' + m2.group(1)

                                self.get_next_line() # To really pass over this continuation syntax line

                        elif len(prev_line) > (m.start(3) - 1) and re.search(r"^\s*$", prev_line[0 : (m.start(3) - 1)]):
                            # TODO: Change name m2.
                            m2 = re.search(r"^(\S.*)", prev_line[(m.start(3) - 1):]) # here has to be something (I can't specify what exactly besides a non space)
                            if m2:
                                #print("Found syntax continuation in prev line")
                                #print(("1st line: {:s}".format(m2.group(1))))
                                #print(("2nd line: {:s}".format(syntax)))

                                syntax = m2.group(1) + ' ' + syntax


                    #print("Encoding: " + ie)
                    #print("syntax:" + syntax)

                    # TODO: handle instruction name
#                     if self.current_inst_name not in self.instructions:
#                         self.instructions[self.current_inst_name] = []

                    self.instructions.append(InstructionDefinition(syntax, ie, self.syntax_behavior_text[-1][1]))

                    self.total_encodings += 1

                    continue


        except ManualParser.OutOfLinesException:
            pass
#             print("End of scipt, out of lines")

        pass

    class OutOfLinesException(Exception):
        pass

    class UnexpectedException(Exception):
        pass


class HeaderParser:
    def __init__(self, header_fn):
        self.header = open(header_fn, 'r')
        self.lines = self.header.read().splitlines()

        self.duplex_inst_encodings = []
        self.other_inst_encodings = []

    def parse(self):
        for l in self.lines:

            # TODO: check out HEXAGON_MAPPING
            #m = re.search(r'^HEXAGON_OPCODE \s* \( \s* " (.*)? " \s* , \s* " (.*)? "', l, re.X)
            m = re.search(r'^{\s* "(.*)?" \s* , \s* "(.*)?"', l, re.X)
            if m:
                syntax = m.group(1)
                encoding = m.group(2).replace(' ', '')

                if len(encoding) != 32:
                    raise UnexpectedException

                # Split intructions: with subinsructions, marked with
                # 'EE' in the 15:14 (from rigth to left) position of their encoding, which
                # are going to be added to the database, and the rest, which only in the
                # case they were not already added from the manual will be included (this is
                # generally undocumented system instructions)

                if encoding[16:18].lower() == 'ee':
                    # I index the array from left to rigth, and just to be sure I'm converting to lower
                    encoding = (encoding[:16] + '00' + encoding[18:]) # '00' - duplex type
                    self.duplex_inst_encodings.append(InstructionDefinition(syntax, encoding, ''))
                else:
                    self.other_inst_encodings.append(InstructionDefinition(syntax, encoding, ''))
#                     print("syntax: " + syntax)
#                     print("encoding: " + encoding)

    def standarize_syntax(self, encodings):
        # To make it look like the manual

        for i in range(len(encodings)):
            syntax = encodings[i].syntax

            # Remove registers size (I'm assuming) from their name:
            # Rd16 -> Rd
#             print("Before: " + syntax)
            syntax = re.sub(r'\b ([RPNMCGS][a-z]{1,2}) \d{0,2} \b', r'\1', syntax, flags=re.X) # TODO: Register all possible register types, s,r,t,e etc.
#             print("After: " + syntax)

            encodings[i].syntax = syntax

# -------------------------------------------------------------------------------------

hex_insn_names = [] # For generating the instruction names header

# TODO: add directions hint
# TODO: Add loop/endloop
# TODO: Support assignments
def generate_name(ins_syntax):
    mname = ""
    # Zero thing - "bla"
    m = re.search(r'^\s*([_a-zA-Z\d]+)\s*$', ins_syntax)
    if m:
        mname = m.group(1)
        # just copy as is
        return mname.upper()

    # First thing - "bla bla insn (bla bla)"
    # extract "insn"()a
    m = re.search(r'([_a-zA-Z\d\.]+)\s*(\(.+\))+\s*.*$', ins_syntax)
    if m:
        mname = m.group(1)
    return mname.upper()

# HACK: just filter out the special characters and we're good to go
# TODO: Find a better way to generate names
def generate_dirtyname(ins_syntax):
    #mname = "".join(e for e in ins_syntax if e.isalnum())
    mname = ins_syntax.replace("!", "_NOT_")
    mname = mname.replace("-=", "_MINUS_EQ_")
    mname = mname.replace("= -", "_EQ_MINUS_")
    mname = mname.replace("+=", "_PLUS_EQ_")
    mname = mname.replace("= +", "_EQ_PLUS_")
    mname = mname.replace("&=", "_AND_EQ_")
    mname = mname.replace("|=", "_OR_EQ_")
    mname = mname.replace("< =", "_LT_EQ_")
    mname = mname.replace("> =", "_GT_EQ_")
    mname = mname.replace("==", "_EQ_")
    mname = mname.translate({ord(c): "_" for c in " !@#$%^&*()[]{};:,./<>?\|`~-=+"})
    return mname.upper()

def generate_insn(ins_tmpl):
    iname = "HEX_INS"
    if ins_tmpl.is_duplex:
        iname += "_DUPLEX"
    else:
        if ins_tmpl.mult_inst:
            iname += "_MULT"
    # Split by ";" for multinstructions and duplexes
    subs = ins_tmpl.syntax.split(";")
    for sub in subs:
        # Extract predicate
        subname = generate_dirtyname(sub)
        iname += "_" + subname

    # There is a weird case when two different instructions have the same syntax
    if iname in hex_insn_names:
        iname += "_"

    return iname

# --------------------------------------------------------------------------------
# Make a new C block (if/case/etc)
# TODO: support more syntax constructs
def make_C_block(lines, begin = None, end = None, ret = None, indent=True):
    new = []
    ws = "\t"
    if not indent:
        ws = ""
    if begin:
        new += [begin + " {"]
    else:
        new += ["{"]
    for l in lines:
        new += [ws + l]
    if ret:
        new += [ws + ret]
    if end:
        new += ["} " + end]
    else:
        new += ["}"]
    return new

# --------------------------------------------------------------------------------
# Associated bits of an instruction field are scattered over the encoding instruction in a whole.
# Here we assemble them by using the mask of the field.
#
# Simple example:
# Let the input mask of an immediate be: 0b1111111110011111111111110
# The bits of the actual immediate need to be concatenated ignoring bit 15:14 and bit 0 (the zeros in the mask).
# So this function returns C-code which shifts the bits of the immediate segments and ORs them to represent a valid value.
#
# hi_u32 is the raw instruction from which we want to concatenate bit 24:16 and bit 13:1 (bit 31:25 are ignored here)
# 10th         2           1
# bit #    432109876 54 3210987654321 0

# Mask:    111111111|00|1111111111111|0
# hi_u32:  100111101|10|1010000010011|0
#              |                 |
#              |                 |
#           +--+ >---------------|-------[shift bit 24:16]
#       ____|____                |     ((hi_u32 & 0x1ff0000) >> 3)
#       1001111010000000000000   |                                   [shift bit 13:1]
# OR             1010000010011 >-+---------------------------------((hi_u32 & 0x3ffe) >> 1))
#       _______________________
# imm = 1001111011010000010011

# imm = ((hi_u32 & 0x1ff0000) >> 3) | ((hi_u32 & 0x3ffe) >> 1))

def make_sparse_mask(num, mask):
    switch = False
    ncount = 0 # counts how many bits were *not* set.
    masks_count = 0 # How many masks we do have
    masks = {}
    bshift = {}
    for i in range(0, 31):
        if (mask >> i) & 1:
            if not switch:
                switch = True
                masks_count += 1
                bshift[masks_count] = ncount
            if masks_count in masks:
                masks[masks_count] |= 1 << i
            else:
                masks[masks_count] = 1 << i
            #bcount -= 1
        else:
            switch = False
            ncount += 1

    # print("MASK") # For grep
    # print(bin(mask))
    # print(masks)
    outstrings = []
    for i in range(masks_count, 0, -1):
        outstrings += ["(({0:s} & 0x{1:x}) >> {2:d})".format(num, masks[i], bshift[i])]
    # print(outstrings)
    outstring = " | ".join(outstrings)
    outstring = "({0:s})".format(outstring)
    return outstring

def find_common_bits(masks_list):
    combits = 0
    for mask in masks_list:
        if combits:
            combits &= mask
        else:
            combits = mask
    return combits

# --------------------------------------------------------------------------------
#                            RIZIN SPECIFIC CODE

preds = {
        "if (Pu)" : "HEX_PRED_TRUE",
        "if (Pv)" : "HEX_PRED_TRUE",
        "if (Pt)" : "HEX_PRED_TRUE",
        "if !Pu " : "HEX_PRED_FALSE",
        "if !Pv " : "HEX_PRED_FALSE",
        "if !Pt " : "HEX_PRED_FALSE",
        "if (Pu.new)" : "HEX_PRED_TRUE_NEW",
        "if (Pv.new)" : "HEX_PRED_TRUE_NEW",
        "if (Pt.new)" : "HEX_PRED_TRUE_NEW",
        "if !Pu.new" : "HEX_PRED_FALSE_NEW",
        "if !Pv.new" : "HEX_PRED_FALSE_NEW",
        "if !Pt.new" : "HEX_PRED_FALSE_NEW",
}

# TODO: How to handle duplex/combined instructions where is a predicate?
# TODO: Extract and set conditional flag based on the instruction
def extract_predicates_rizin(ins_tmpl):
    lines = []
    for k,v in preds.items():
        if ins_tmpl.syntax.startswith(k):
            pred = "{0:s} = {1:s}; // {2:s}".format("hi->predicate", v, k)
            lines = [pred]
    if not lines:
        lines = ["{0:s} = HEX_NOPRED;".format("hi->predicate")]
    return lines

pfs = {
    ":rnd" : "HEX_PF_RND",
    ":crnd" : "HEX_PF_CRND",
    ":raw" : "HEX_PF_RAW",
    ":chop" : "HEX_PF_CHOP",
    ":sat" : "HEX_PF_SAT",
    ":hi" : "HEX_PF_HI",
    ":lo" : "HEX_PF_LO",
    ":<<1" : "HEX_PF_LSH1",
    ":<<16" : "HEX_PF_LSH16",
    ":>>1" : "HEX_PF_RSH1",
    ":neg" : "HEX_PF_NEG",
    ":pos" : "HEX_PF_POS",
    ":scale" : "HEX_PF_SCALE",
    ":deprecated" : "HEX_PF_DEPRECATED"
}

def extract_pf_rizin(ins_tmpl):
    lines = []
    pfssorted = collections.OrderedDict(sorted(pfs.items()))
    for k,v in pfssorted.items():
        if k in ins_tmpl.syntax:
            pf = "{0:s} |= {1:s}; // {2:s}".format("hi->pf", v, k)
            lines += [pf]
    return lines

def extract_name_rizin(ins_tmpl):
    lines = []
    lines += ["hi->instruction = {0:s};".format(ins_tmpl.name)]
    return lines

def extract_fields_rizin(ins_tmpl):
    lines = []
    sortf = lambda c: ins_tmpl.operands[c].index
    sortedfields = sorted(ins_tmpl.encoding.fields, key = sortf)
    op_count = 0
    # Set DUPLEX flag for those instructions
    if ins_tmpl.is_duplex:
        lines += ["hi->duplex = true;"]
    # Handle branch specific fields
    is_branch = False
    if ins_tmpl.branch and ins_tmpl.branch.target:
        is_branch = True
        ti = ins_tmpl.branch.target.index # Target operand index
    # if this is a loop, also mark it as a branch and get target
    if "loop" in ins_tmpl.syntax:
        is_branch = True
        ti = 0 # Always 0

    for n in sortedfields:
        f = ins_tmpl.encoding.fields[n]
        i = ins_tmpl.operands[n].index
        slines = []

        if f.no_mask_split:
            mask = "((({0:s}) & 0x{1:x}) >> {2:d})".format("hi_u32", f.mask, f.mask_lower_pos)
        else:
            # Merge bits into the groups first, for the sake of speed
            mask = make_sparse_mask("hi_u32", f.mask)

        fieldtype = "HEX_OP_TYPE_IMM"
        if isinstance(ins_tmpl.operands[n], RegisterTemplate):
            fieldtype = "HEX_OP_TYPE_REG"
            # 1. Check if predicate register
            if ins_tmpl.operands[n].is_predicate:
                fieldtype = "HEX_OP_TYPE_PREDICATE"
                val = "hi->ops[{0:d}].op.pred = {1:s};".format(i, mask)
            # 2. Check if control register
            elif ins_tmpl.operands[n].is_control:
                fieldtype = "HEX_OP_TYPE_CONTROL"
                val = "hi->ops[{0:d}].op.cr = {1:s};".format(i, mask)
            # 3. Check if system control register
            elif ins_tmpl.operands[n].is_system:
                fieldtype = "HEX_OP_TYPE_SYSTEM"
                val = "hi->ops[{0:d}].op.sys = {1:s};".format(i, mask)
            # 4. Usual register
            else:
                fieldtype = "HEX_OP_TYPE_REG"
                if ins_tmpl.operands[n].is_register_pair:
                    # TODO: Handle additional attributes
                    val = "hi->ops[{0:d}].op.reg = {1:s};".format(i, mask)
                else:
                    val = "hi->ops[{0:d}].op.reg = {1:s}; // {2:s}".format(i, mask, ins_tmpl.operands[n].syntax)
        # Optional value
        elif isinstance(ins_tmpl.operands[n], OptionalTemplate):
            fieldtype = "HEX_OP_TYPE_OPT"
        # Immediate value
        else:
            val = "hi->ops[{0:d}].op.imm = {1:s}".format(i, mask)
            # Perform sign extension (also applies to jump targets...)
            # Also applies to the loops

            if ins_tmpl.operands[n].signed or (is_branch and i == ti):
                # The immediate is already scaled at this point. Therefore the most significant bit is bit 24 (if we assume #r22:2)
                signmask = "hi->ops[{0:d}].op.imm & (1 << {1:d})".format(i, f.mask_len + ins_tmpl.operands[n].scaled - 1)
                signext = "hi->ops[{0:d}].op.imm |= (0xFFFFFFFF << {1:d});".format(i, f.mask_len + ins_tmpl.operands[n].scaled - 1)
                slines += make_C_block([signext], "if ({0:s})".format(signmask))
            # Handle scaled operands
            if ins_tmpl.operands[n].scaled:
                val += " << {0:d}; // scaled".format(ins_tmpl.operands[n].scaled)
            else:
                val += ";"

        # We do not have operand for optional, so handle it's differently
        if fieldtype == "HEX_OP_TYPE_OPT":
            # Add IF here, because optional
            opsft = "{0:s} |= {1:s}; // {2:s}".format("hi->pf", "HEX_PF_LSH1", "[:<<1]")
            lines += make_C_block([opsft], "if ({0:s})".format(mask))
        else:
            field = "hi->ops[{0:d}].type = {1:s};".format(i, fieldtype)
            opattrs = []
            if isinstance(ins_tmpl.operands[n], RegisterTemplate):
                # Check if a register pair
                if ins_tmpl.operands[n].is_register_pair:
                    opattrs += ["hi->ops[{0:d}].attr |= HEX_OP_REG_PAIR;".format(i)]
            lines += [field] + opattrs + [val]
            lines += slines
            op_count += 1 # Count only non-optional operands

    lines = ["hi->op_count = {0:d};".format(op_count)] + lines
    return lines

def extend_immediates_rizin(ins_tmpl):
    elines = []
    # Note about duplex containers:
    # In duplex containers only the second of two instructions (slot 1) can be expanded.
    # Slot 1 are the high bits of an instruction, therefore:
    #  SLOT 1  ;    SLOT 0
    # Rd = #u6 ; allocframe(#u5)
    # The manual speaks of only two specific instructions (Rx = add (Rx, #s7) and Rd = #u6)
    # which are expandable (But there seem to be more)
    # Reference: Programmers Manual V62-V67 Chapter 10.3

    if ins_tmpl.name in extendable_insn or (ins_tmpl.is_duplex \
         and ins_tmpl.syntax.split(';', 1)[0].strip() in extendable_duplex_syntax):
        if ins_tmpl.imm_ops:
            # Assume we only have one - it is clear in the list
            op = ins_tmpl.imm_ext_op # imm_ext_op is by default set to imm_ops[0]
            oi = op.index # Immediate operand index
            # If there is an offset of the operand - apply it too
            # Use "extend_offset(op, off)" function then
            off = op.scaled
            if off:
                elines = ["hex_op_extend_off(&hi->ops[{0:d}], {1:d});".format(oi, off)]
            else:
                elines = ["hex_op_extend(&hi->ops[{0:d}]);".format(oi)]
    return elines

def extract_mnemonic_rizin(ins_tmpl):
    lines = []
    # field -> token
    sortf = lambda c: ins_tmpl.operands[c].index
    sortedops = sorted(ins_tmpl.operands, key = sortf)
    fmt = {}
    args = []
    fmtstr = ins_tmpl.syntax
    for n in sortedops:
        o = ins_tmpl.operands[n]
        i = ins_tmpl.operands[n].index
        if isinstance(o, RegisterTemplate):
            if o.is_predicate:
                fmt[o.syntax] = "P%d" # + number from mask
                args += ["hi->ops[{0:d}].op.pred".format(i)]
            elif o.is_control:
                if o.is_register_pair:
                    fmt[o.syntax] = "%s:%s"
                    args += ["hex_get_cntl_reg(hi->ops[{0:d}].op.cr + 1)".format(i)]
                    args += ["hex_get_cntl_reg(hi->ops[{0:d}].op.cr)".format(i)]
                else:
                    fmt[o.syntax] = "%s"
                    args += ["hex_get_cntl_reg(hi->ops[{0:d}].op.cr)".format(i)]
            elif o.is_system:
                if o.is_register_pair:
                    fmt[o.syntax] = "%s:%s"
                    args += ["hex_get_sys_reg(hi->ops[{0:d}].op.sys + 1)".format(i)]
                    args += ["hex_get_sys_reg(hi->ops[{0:d}].op.sys)".format(i)]
                else:
                    fmt[o.syntax] = "%s"
                    args += ["hex_get_sys_reg(hi->ops[{0:d}].op.sys)".format(i)]
            else:
                # DUPLEX
                if ins_tmpl.is_duplex:
                    if o.is_register_pair:
                        fmt[o.syntax] = "%s" # + number from mask
                        args += ["hex_get_sub_regpair(hi->ops[{0:d}].op.reg)".format(i)]
                    else:
                        fmt[o.syntax] = "%s" # + number from mask
                        args += ["hex_get_sub_reg(hi->ops[{0:d}].op.reg)".format(i)]
                # NOT DUPLEX
                else:
                    if o.is_register_pair:
                        fmt[o.syntax] = "R%d:R%d" # + number from mask
                        args += ["hi->ops[{0:d}].op.reg + 1".format(i)]
                        args += ["hi->ops[{0:d}].op.reg".format(i)]
                    else:
                        fmt[o.syntax] = "R%d" # + number from mask
                        args += ["hi->ops[{0:d}].op.reg".format(i)]
        elif isinstance(o, OptionalTemplate):
            fmt[o.syntax] = "%s"
            args += ["((hi->pf & HEX_PF_LSH1) == HEX_PF_LSH1) ? \":<<1\" : \"\""]
        elif isinstance(o, ImmediateTemplate):
            fmt[o.syntax] = "0x%x" # TODO: Better representation, etc
            # As soon as we extract the classes from the encoded instructions this should its info from it.
            if ("JUMP_" in ins_tmpl.name or "CALL_" in ins_tmpl.name) and (i == len(ins_tmpl.operands)-1):
                args += ["addr + (st32) hi->ops[{0:d}].op.imm".format(i)]
            elif o.signed:
                fmt[o.syntax] = "%d"
                args += ["(st32) hi->ops[{0:d}].op.imm".format(i)]
            else:
                args += ["hi->ops[{0:d}].op.imm".format(i)]
        else:
            pass

    for k,v in fmt.items():
        fmtstr = fmtstr.replace(k,v,1)
    if args:
        mnem = "sprintf(hi->mnem, \"" + fmtstr + "\", "
        mnem += ", ".join(args)
        mnem += ");"
    else:
        mnem = "sprintf(hi->mnem, \"" + fmtstr + "\");"

    if mnem:
        lines += [mnem]

    return lines

def form_instruction_rizin(category, instruction):
    inlines = []
    inlines += ["// Instruction: {0}: {1} | {2}".format(category, instruction.encoding.text, instruction.syntax)]
    inlines += extract_name_rizin(instruction)
    inlines += extract_fields_rizin(instruction)
    inlines += extract_predicates_rizin(instruction)
    inlines += extract_pf_rizin(instruction)
    inlines += extend_immediates_rizin(instruction)
    inlines += extract_mnemonic_rizin(instruction)
    return inlines

def const_extender_rizin():
    clines = ["// Handle constant extender"]
    clines += ["hi->instruction = HEX_INS_IMMEXT;"]
    clines += ["hi->op_count = 1;"]
    clines += ["hi->ops[0].type = HEX_OP_TYPE_IMM;"]
    clines += ["hi->ops[0].attr |= HEX_OP_CONST_EXT;"]
    clines += ["hi->ops[0].op.imm = ((hi_u32 & 0x3FFF) | (((hi_u32 >> 16) & 0xFFF) << 14)) << 6;"]
    clines += ["constant_extender = hi->ops[0].op.imm;"]
    clines += ["sprintf(hi->mnem, \"immext(#0x%x)\", hi->ops[0].op.imm);"]
    return clines

def write_files_rizin(ins_class, ins_duplex, hex_insn_names, extendable_insn):
    HEX_DISAS_FILENAME = "rizin/hexagon_disas.c"
    HEX_INSN_FILENAME = "rizin/hexagon_insn.h"
    HEX_ANALYSIS_FILENAME = "rizin/hexagon_analysis.c"
    auto_header = ["// THIS FILE IS AUTOGENERATED - SEE IMPORTER.PY FILE", ""]
    spdx = ["// SPDX-FileCopyrightText: 2018-2021 Anton Kochkov <anton.kochkov@gmail.com>", "// SPDX-License-Identifier: LGPL-3.0-only", ""]
    header_guard = ["#ifndef HEXAGON_INSN_H", "#define HEXAGON_INSN_H", ""]

    # FIXME: Dirty hack but ENOTIME!
    ins_enum = ["HEX_INS_UNKNOWN,"] # Unknown instruction
    ins_enum += ["HEX_INS_IMMEXT,"] # Constant extender
    for i in hex_insn_names:
        ins_enum += [i + ","]
    hlines = make_C_block(ins_enum, "enum HEX_INS")
    hlines[-1] = hlines[-1] + ";" # Finish the enum with semicolon
    lines = auto_header + spdx + header_guard + hlines + ["", "#endif"]
    with open(HEX_INSN_FILENAME, "w") as f:
        for l in lines:
            f.write(l + "\n")

    # At first - generate code for parsing duplexes
    # -----------------------------------------------------------------------------
    lines = ["// DUPLEXES"]
    inlines = []
    cat_switch = "switch ((((hi_u32 >> 29) & 0xF) << 1) | ((hi_u32 >> 13) & 1))"
    dupsorted = collections.OrderedDict(sorted(ins_duplex.items()))
    for k,v in dupsorted.items():
        vlines = []
        # Match by category, in hex format
        case_beg = "case 0x{0:x}:".format(k)
        for i in v:
            # TODO: Extract common markers, rebalance to switches
            mask = i.encoding.mask
            val = i.encoding.value
            vlines += make_C_block(form_instruction_rizin(k, i), "if ((hi_u32 & 0x{0:x}) == 0x{1:x})".format(mask, val), None, "break;")
        inlines += make_C_block(vlines, case_beg, None, "break;")
    inlines = make_C_block(inlines, cat_switch)
    # Run duplexes only if parse bits are set
    lines += make_C_block(inlines, "if (((hi_u32 >> 14) & 0x3) == 0)")

    # Now handle the non-compressed instructions
    # -------------------------------------------------------------------------------
    inlines = []
    cat_switch = "switch ((hi_u32 >> 28) & 0xF)"
    # At first - handle constant extender
    const_case = "case 0x0:"
    clines = const_extender_rizin()
    inlines += make_C_block(clines, const_case, None, "break;")
    # Then generate code for usual instructions
    classsorted = collections.OrderedDict(sorted(ins_class.items()))
    for k,v in classsorted.items():
        vlines = []
        # Match by category, in hex format
        case_beg = "case 0x{0:x}:".format(k)
        for i in v:
            # TODO: Extract common markers, rebalance to switches
            mask = i.encoding.mask & ~(0xf << 28)
            val = i.encoding.value & ~(0xf << 28)
            vlines += make_C_block(form_instruction_rizin(k, i), "if ((hi_u32 & 0x{0:x}) == 0x{1:x})".format(mask, val), None, "break;")
        inlines += make_C_block(vlines, case_beg, None, "break;")
    inlines = make_C_block(inlines, cat_switch)
    lines += make_C_block(inlines, "else") # only run if non-duplex mode

    # Produce a RzAsm plugin C file finally
    # ---------------------------------------------------------------------------------
    includes = ["#include <stdio.h>"]
    includes += ["#include <stdbool.h>"]
    includes += ["#include <rz_types.h>"]
    includes += ["#include <rz_util.h>"]
    includes += ["#include <rz_asm.h>"]
    includes += ["#include \"hexagon.h\""]
    includes += ["#include \"hexagon_insn.h\""]
    includes += [""] # for the sake of beauty

    # Add constantExtender definition
    includes += ["extern ut32 constant_extender;"]
    includes += [""] # for the sake of beauty

    # Add gcc deoptimization attribute for Rizin CI ASAN build
    deoptimize_if_asan = ["#if ASAN"]
    deoptimize_if_asan += ["#define NO_OPT_IF_ASAN __attribute__((optimize(0)))"]
    deoptimize_if_asan += ["#else"]
    deoptimize_if_asan += ["#define NO_OPT_IF_ASAN"]
    deoptimize_if_asan += ["#endif"]
    deoptimize_if_asan += [""] # for the sake of beauty

    # Wrap everything into one function
    lines = auto_header + spdx + includes + deoptimize_if_asan + \
        make_C_block(lines, "NO_OPT_IF_ASAN int hexagon_disasm_instruction(ut32 hi_u32, HexInsn *hi, ut32 addr)", None, "return 4;")
    with open(HEX_DISAS_FILENAME, "w") as f:
        for l in lines:
            f.write(l + "\n")

    # Generate analysis code
    # ---------------------------------------------------------------------------------

    type_switch = "switch (hi->instruction)"
    emulines = []
    for i in deco.inst_template_list:
        ilines = []
        if i.branch:
            if isinstance(i.branch.target, ImmediateTemplate):
                ilines += ["// {0:s}".format(i.syntax)]

                if i.branch.type == "call":
                    ilines += ["op->type = RZ_ANALYSIS_OP_TYPE_CALL;"]
                    ilines += ["op->jump = op->addr + (st32) hi->ops[{0:d}].op.imm;".format(i.branch.target.index)]
                else:
                    if i.branch.is_conditional:
                        ilines += ["op->type = RZ_ANALYSIS_OP_TYPE_CJMP;"]
                    else:
                        ilines += ["op->type = RZ_ANALYSIS_OP_TYPE_JMP;"]
                    ilines += ["op->jump = op->addr + (st32) hi->ops[{0:d}].op.imm;".format(i.branch.target.index)]
                    ilines += ["op->fail = op->addr + op->size;"]
                emulines += make_C_block(ilines, "case {0:s}:".format(i.name), None, "break;")
            if i.branch.type == "dealloc_return":
                ilines += ["// {0:s}".format(i.syntax)]
                ilines += ["op->type = RZ_ANALYSIS_OP_TYPE_RET;"];
                emulines += make_C_block(ilines, "case {0:s}:".format(i.name), None, "break;")

    emulines = make_C_block(emulines, type_switch, indent=False)
    # Wrap everything into one function
    lines = make_C_block(emulines, "int hexagon_analysis_instruction(HexInsn *hi, RzAnalysisOp *op)", None, "return op->size;")

    # Produce a RzAsm plugin C file finally
    # ---------------------------------------------------------------------------------
    includes = ["#include <stdio.h>"]
    includes += ["#include <stdbool.h>"]
    includes += ["#include <rz_types.h>"]
    includes += ["#include <rz_util.h>"]
    includes += ["#include <rz_asm.h>"]
    includes += ["#include <rz_analysis.h>"]
    includes += ["#include \"hexagon.h\""]
    includes += ["#include \"hexagon_insn.h\""]
    includes += [""] # for the sake of beauty
    lines = auto_header + spdx + includes + lines

    with open(HEX_ANALYSIS_FILENAME, "w") as f:
        for l in lines:
            f.write(l + "\n")


    # TODO: Export the sources into rizin repository

# ------------------------------------------------------------------------------------

if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print("This script needs Python version 3.7 or higher")
        sys.exit()

    parser = argparse.ArgumentParser(description="Hexagon C disassembly generator")
    args = parser.parse_args()
    mp = ManualParser('80-n2040-36_b_hexagon_v62_prog_ref_manual.txt')
    mp.go_to_instruction_set_start()
    mp.find_encondings()

    hp = HeaderParser('hexagon_iset_v5.h')
    hp.parse()
    # So here we have objects of parsed tokens
    hp.standarize_syntax(hp.duplex_inst_encodings)
    hp.standarize_syntax(hp.other_inst_encodings)
    inst_def_list = mp.instructions
    inst_def_list.extend(hp.duplex_inst_encodings)
    #inst_def_list.extend(hp.other_inst_encodings)
    #print(inst_def_list)

    deco = HexagonInstructionDecoder(inst_def_list)
    ins_class = {} # We pre-sort our instructions by ICLASS value
    ins_duplex = {} # We pre-sort our duplex instructions by ICLASS too
    for ins_tmpl in deco.inst_template_list:
        hex_inst_struc = {}
        hex_inst_struc["mask"] = ins_tmpl.encoding.mask
        hex_inst_struc["syntax"] = ins_tmpl.syntax
        ins_tmpl.name = generate_insn(ins_tmpl)
        hex_insn_names += [ins_tmpl.name] # for instructions header enum
        # separate parsing duplex instructions into another thing
        dupbits = ins_tmpl.encoding.text[16:18]
        duplex = 1
        if not dupbits == 'PP':
            duplex = int(dupbits, 2)

        if not duplex == 0:
            # for non-duplex instructions those are higher 4 bits
            iclass = int(ins_tmpl.encoding.text[0:4], 2)
            #print("{0} : {1} - {2}".format(iclass, ins_tmpl.encoding.text, ins_tmpl.syntax))
            #for tok in ins_tmpl.tokens:
            #    print("{0} : {1}".format(tok.s, tok.op))
            if iclass in ins_class:
                ins_class[iclass] += [ins_tmpl]
            else:
                ins_class[iclass] = [ins_tmpl]
        else:
            # for duplex instructions those are high 3 bits + 13 bit
            iclass = int(ins_tmpl.encoding.text[0:3] + ins_tmpl.encoding.text[18], 2)
            if iclass in ins_duplex:
                ins_duplex[iclass] += [ins_tmpl]
            else:
                ins_duplex[iclass] = [ins_tmpl]

    # -----------------------------------------------------------------------------------------------
    # Now parse the list of the instructions which are support the constant extender system
    for i in deco.inst_template_list:
        print(i.syntax)
    extendable_insn = [] # The list of extendable instructions' names
    extendable_duplex_syntax = []
    with open("const_extenders.txt") as f:
        ext_ins = f.read().splitlines()
        for ins_tmpl in deco.inst_template_list:
            for ext_syntax in ext_ins:
                normsyntax = standarize_syntax_objdump(ext_syntax.split('/', 1)[0])
                if ext_syntax.split('//')[-1].strip() == "Slot 1 duplex":
                    extendable_duplex_syntax += [normsyntax.strip()]
                #print("{0:s} VS {1:s}".format(ins_tmpl.syntax, normsyntax))
                if ins_tmpl.syntax == normsyntax:
                    extendable_insn += [ins_tmpl.name]
                    print("{0:s} - {1:s}".format(ins_tmpl.name, ins_tmpl.syntax))

    # -----------------------------------------------------------------------------------------------
    #                                      TOOL SPECIFIC CODE
    # Rizin specifics
    write_files_rizin(ins_class, ins_duplex, hex_insn_names, extendable_insn)
    print("Succesfully generated Rizin disassembly and analysis plugin")

