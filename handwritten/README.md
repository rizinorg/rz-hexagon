Some instructions are not parsed by the disassembler generator, because they are irrelevant for it.
`endloop` instructions are one example.

The names used in QEMU for them, can be added to `misc_il_insn.json`.
They will be written to `hexagon_il_non_insn_ops.c` and declared in `hexagon_il.h`.

If you need to define an arbitrary sub-routine,
you can add it in `rzil_compiler/Resources/Hexagon/sub_routines.json`.