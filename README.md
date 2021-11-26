<!--
SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>

SPDX-License-Identifier: LGPL-3.0-only
-->

# rz-hexagon

This is a Hexagon disassembly and analysis plugin generator for `rizin`.
It uses the [LLVM target description source code](https://github.com/llvm/llvm-project/tree/main/llvm/lib/Target/Hexagon)
of the Hexagon architecture and additional hand-written code.

# Missing features and bugs

This plugin is under continuous work. So checkout the Github issues for missing features or not yet fixed bugs.

# Prerequisites

### Requirements

- For formatting we need `clang-format-13`. If it is not available on your distribution, you can install it from https://apt.llvm.org/.

- Python requirements are in `requirements.txt`
### Hexagon Target Description

We take all the information about the Hexagon instructions and operands from the many LLVM target description files.

Luckily there is a tool which combines all the information of those files into one `.json` file which we name `Hexagon.json`. 
So `Hexagon.json` will hold all information about the Hexagon instructions and operands.

In order to generate the `Hexagon.json` file we need the `llvm-tblgen` binary.

Unfortunately `llvm-tblgen` is usually not provided via the package manager. You have to compile LLVM by yourself.

### Build LLVM

Please follow the [LLVM docs](https://llvm.org/docs/GettingStarted.html#getting-the-source-code-and-building-llvm)
(Build the release version to save **a lot** of RAM).

`llvm-tblgen` should be in `<somewhere>/llvm-project/bin/` after the build.

### Build and move Hexagon.json

```bash
cd llvm-project/llvm/lib/Target/Hexagon
llvm-tblgen -I ../../../include/ --dump-json -o Hexagon.json Hexagon.td
mv Hexagon.json <path to>/rz-hexagon/
```

# Install

```bash
cd rz-hexagon/
pip install -r requirements.txt
# If you enjoy some colors
pip install -r optional_requirements.txt
# Run tests
cd Tests
python3 -m unittest discover -s . -t .
# Install as develop package
cd ..
pip install -e .
```

# Generate PlugIn

Simply run:
```
./LLVMImporter.py
```

It processes the files and generates C code in `./rizin` and its subdirectories.

Copy the generated files to the `rizin` directory with
  ```commandline
  rsync -a rizin/ <rz-src-path>/
  ```

# Porting

Apart from some methods, which produce the C code for `rizin`, this code is `rizin` independent.
In theory, it shouldn't be that hard to use it for disassembler plugins of other reverse engineering frameworks.

So here are some good to know points for porting:
- All `rizin` specific methods have the leading comment: `# RIZIN SPECIFIC`.
- Please open an issue if you start working on this code for another reverse engineering framework.
  We could remove all `rizin` code from this repo and fork our framework specific plugins from it.

# Development info

- The best way to start is to take a look at an instruction in `Hexagon.json`.
  We take all information from there and knowing the different objects
  makes it easier to understand the code.
- If you need any information about a llvm specific term or variable name from the `Hexagon.json` file a simple
  `grep -rn "term" llvm-project/llvm/lib/Target/Hexagon/` will usually help.
- If you parse LLVM data always end it with an exception else statement:
  ```python
  if x:
     ...
  elif y:
     ...
  elif z:
     ...
  else:
    raise ImplementationException("This case seems to be new, please add it.")
  ```
- Names of variables which holds data directly taken from the `Hexagon.json` file
  should have a name which starts with
`llvm_`.
  
  For example:
  
  - `llvm_in_operands` holds a list with the content of `Hexagon.json::[Instr].InOperandList`.
  - `llvm_syntax` holds: `$Rdd8 = combine(#0,#$Ii) ; $Rx16 = add($Rx16in,$Rs16)` (the syntax in LLVM style).

    In case of this duplex Instruction it is actually the LLVM-syntax of the high and
    low instruction concatenated with a semicolon.
  - `syntax` holds: `Rdd = combine(#0,#Ii) ; Rx = add(Rxin,Rs)`
  - `Instruction.operands` is a dictionary which contains `Register` and `Immediate` Python objects.

- Please take a brief look at the [Rizin development](https://github.com/rizinorg/rizin/blob/dev/DEVELOPERS.md) guide if you plan to change C code.

# Contributors

* Rot127

* Anton Kochkov

