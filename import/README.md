LLVM does not define all instructions and registers. That's why we have to import them from the manual.
`import_instructions.py` parses a `.txt` version of the SYSTEM chapter, parses the encoding, asm string and name into an LLVM style and stores it as `.json` file.

`gen_registers.py` does the same for a given list of registers. The list of system registers can be retrieved by compiling assembly instructions which use all system registers once. Afterwards it can be decompiled with the SDKs `objdump`.

The `.json` files are than used by `LLVMImporter.py` to update the LLVM definitions.

It is important to keep in mind, that the instruction and register templates only set those values to a correct value, which are currrently used by `LLVMImport.py`.