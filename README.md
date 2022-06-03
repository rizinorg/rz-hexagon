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

- For formatting we need `clang-format`. If it is not available on your distribution, you can install it from https://apt.llvm.org/.

- Python requirements are in `requirements.txt`
- As a developer you also need `black`, `flake8`, `reuse`.

### Hexagon Target Description

We take all the information about the Hexagon instructions and operands from the many LLVM target description files.

Luckily there is a tool which combines all the information of those files into one `.json` file which we name `Hexagon.json`. 
So `Hexagon.json` will hold all information about the Hexagon instructions and operands.

In order to generate the `Hexagon.json` file we need the `llvm-tblgen` binary.

Unfortunately `llvm-tblgen` is usually not provided via the package manager. You have to compile LLVM by yourself.

### Build LLVM

Please follow the [LLVM docs](https://llvm.org/docs/GettingStarted.html#getting-the-source-code-and-building-llvm)
(Build the release version to save **a lot** of RAM).

`llvm-tblgen` should be in `<somewhere>/llvm-project/build/bin/` after the build.

Please add this directory to your `PATH`.

# Install

**Python 3.11**

We require `Python 3.11`. Please follow the install-instructions from the [Python documentation](https://docs.python.org/3.11/). 

**Clone repository**

```bash
git clone --recurse-submodules https://github.com/rizinorg/rz-hexagon.git
cd rz-hexagon/
```

**Setup a virtual environment**

```bash
python3 -m venv .venv
# Activate the virtual environment.
# This step might differ from shell to shell (the one below is for bash/zsh).
# Take a look at the Python docs if you are using another one.
# https://docs.python.org/3.11/library/venv.html?highlight=virtual%20environment
source .venv/bin/activate
```

**Install `rz-hexagon` as package**

```bash
pip3 install -r requirements.txt -r rzil_compiler/requirements.txt
# If you enjoy some colors
pip3 install -r optional_requirements.txt
# Install as develop package
pip3 install -e rzil_compiler/
pip3 install -e .
```

# Generate PlugIn

The first time you run the generator you need to add the `-j` option.
This will generate the `Hexagon.json` from the current `LLVM` source.
```
./LLVMImporter.py -j
```

It processes the LLVM definition files and generates C code in `./rizin` and its subdirectories.

Copy the generated files to the `rizin` directory with
  ```commandline
  rsync -a rizin/ <rz-src-path>/
  ```

## Test

You can run the tests with:
```bash
cd Tests
python3 -m unittest discover -s . -t .
```

# Development info

**Before you open a PR please run and fix the warnings.:
```bash
black -l 120 $(git ls-files '*.py')
flake8 --select=W504 --ignore=E203,W503 --max-line-length=120 $(git ls-files '*.py')
reuse lint
```

### Coding info
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
  - `llvm_syntax` holds: `$Rdd8 = combine(#0,#$Ii)` (the syntax in LLVM style).
  - `syntax` holds: `Rdd = combine(#0,#Ii)` (cleaned up LLVM syntax)
  - `Instruction.operands` is a dictionary which contains `Register` and `Immediate` Python objects.

- Please take a brief look at the [Rizin development](https://github.com/rizinorg/rizin/blob/dev/DEVELOPERS.md) guide if you plan to change C code.

# Contributors

* Rot127
* Anton Kochkov
* Florian Märkl
