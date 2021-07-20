// Please use the Hexagon SDK to write those tests and hexagon-llvm-objdump to confirm the disassembly.
// This prevents mistakes.
asmTest:
	{  // General instr., immext(##0)
	  R31 = add(R0, ##0x2)
	  R0 = #0x101
	}
	{  // Compund instr. pos. jump
	  p0 = tstbit(R6,#0); if (!p0.new) jump:t 8
	}
	{  // Compund instr. neg. jump
	  p0 = tstbit(R6,#0); if (!p0.new) jump:t #-8
	}
	{  // Nop, immext.
	  R31 = add(R0, ##0x40)
	  R0 = #0x101
	  nop
	}
	{  // Duplex
	  R0 = #-1
	  R7 = #4
	}
	{  // Duplex, GeneralDoubleLow8Regs, predicate
	  if (P0) dealloc_return
	  R1:0 = memd(r29+#64)
	}
	{  // Duplex, GeneralDoubleLow8Regs
	  if (!P0) dealloc_return
	  R7:6 = memd(r29+#64)
	}
	{  // Duplex, GeneralDoubleLow8Regs
	  jumpr R4
	  R23:22 = combine(#0,#2)
	  R17:16 = memd(r29+#64)
	}
	{  // Duplex, predicates, .new
	  P0 = R13
	  if (!P0.new) R23 = #0
	  jumpr R31
	}
	{  // n1Const
	  R5=add(clb(R31),#-1)
	}
	{  // Negative numbers
	  R4=add(R19,#-0xabcd)
	}
	{  // GuestRegs64, GuestRegs
	  G9:8 = R9:8
	}
	{  // GuestRegs
      GELR = R31
	}
	{  // ModRegs
	  R11:10 = memb_fifo(R12++M0:brev)
	  R15:14 = memb_fifo(R7=#0x3)
	}
	{  // Failes: CtrRegs64
	  C21:20 = R19:18
	}
	{  // CtrRegs64
	  C17:16 = R19:18
	}
	{  // CtrRegs64. Alias
      C19:18 = R31:30
	}
	{  // Loop
	  loop0(#4, #16)
	}
	{
	  nop
	}
	{
	  nop
	}:endloop0

	loop0(#4, #3)
	{
	  P0 = R13
	  R23:22 = memb_fifo(R27=#0x3)
	}
	loop1(#4, #2)
	{
	  nop
	  R7=R28
	  memb(R10=#7)=R4
	}
	{
	  R4=R3
	}:endloop01
	jump #0
		jump #0
			jump #0
	loop0(#4, #3)
	{
	  P0 = R13
	  R23:22 = memb_fifo(R27=#0x3)
	}
	jump #0


	loop1(#4, #2)
	{
	  nop
	  R7=R28
	}:endloop1
	{
	  R4=R3
	}:endloop0

	loop1(#4, #3)
	{
	  P0 = R13
	  R23:22 = memb_fifo(R27=#0x3)
	}
	jump #0


	loop0(#4, #2)
	{
	  R7=R28
	}:endloop0
	{
	  R4=R3
	}:endloop1

	/*
	{  // HVX Instructions which are missing in the public documentation.
	   // HvxVR, HvxVQR (InOutRegs: Vy), IntRegsLow8, InOutRegs (Rx)
	   // Also, it seems that the SDK does not support that man HVX isntructions.
      V3.w += vr8mpyz(V1.n,R7.b++)
	}
		{
	  V15:14.w += vmpy(V2.h,R27.h):sat
	  V15:14.uw = vmpy(V31.uh,V14.uh)
	}
	{
	  vhist128
	}*/

	.falign
