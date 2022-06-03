Add a register here for import:
- `cp ../Register-template.json UNDOCUMENTED_RegisterName.json`
- Set data within the `UNDOCUMENTED_RegisterName.json`
- Done. `LLVMImporter` will add the register.

If you need to add a register which already belongs to a certain class, simply name the file `<RegClass>-<RegName>,json`.
So for the `C20` register it would be `CtrRegs-C20.json`.

Same logic applies for register classes (like `SysRegs64-template.json`).