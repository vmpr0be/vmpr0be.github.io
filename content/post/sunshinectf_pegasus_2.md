+++
author = "vmpr0be"
title = "SunshineCTF 2025 - Access Code"
date = "2025-09-29"
categories = ["ctf"]
+++

### Overview

We are given 6 files:
- `runpeg`: an interpreter and debugger for the Pegasus bytecode.
- `libear.so`/`libeardbg.so`: libraries used by `runpeg`.
- `AccessCode.peg`: the executable to be interpreted in Pegasus format.  
- `EAR_EAR_v3.md`/`PEGASUS.md`: documentation for the bytecode and the Pegasus format.

To start interpreting the `AccessCode.peg` executable, run: 

```bash
runpeg <file.peg> [--debug] [--verbose] [--trace]
```

### Reversing

We'll run the executable to gather information about its behavior.

```bash
./runpeg AccessCode.peg

Input security access code:
> supersecret
Invalid access code, please try again.
Input security access code:
> something
Invalid access code, please try again.
Input security access code:
> letmein
Invalid access code, please try again.
If you forgot the security access code, please type "forgot".
Input security access code:
> forgot
Hint: hash(access_code) = "f33e5289cd2d110546cc1dce76affff61faef703ed4e2a3580baee52f7c10cdb"
```

After several attempts, the program tells us we can use the `forgot` command to get a hint: a hash of the actual password.

We can use the embedded debugger in the interpreter to disassemble the bytecode and see how the program runs.

```python
./runpeg AccessCode.peg --debug

(dbg) vmmap
0000-00FF: R=INV::FF W=INV::FF X=INV::FF
0100-02FF: R=02:0000 W=INV::FF X=INV::FF  @PEG
0300-08FF: R=02:0200 W=INV::FF X=02:0200  @TEXT
0900-09FF: R=02:0800 W=INV::FF X=INV::FF  @CONST
0A00-0AFF: R=02:0900 W=INV::FE X=INV::FF  @DATA
0B00-F9FF: R=INV::FF W=INV::FF X=INV::FF
FA00-FDFF: R=INV::F0 W=INV::F0 X=INV::FF  @STACK
FE00-FFFF: R=INV::FF W=INV::FF X=INV::FF
```

There are multiple memory segments. One of them is named `@TEXT` and ranges from `0x300` to `0x8FF`; it contains the executable code (similar to a `.text` section). Let's disassemble it.


```python
(dbg) disassemble 500 0x300
@puts:
        0300.0000: MOV     A3, 0x7F
        ...
@print_hex_byte:
        0314.0000: ADD     A5, PC, 0x3A
        ...
@print_hex:
        032D.0000: MOV     A1, A1
        ...
@gimli_dump_state:
        0363.0000: PSH     {S0-S1, FP, RA-RD}
        ...
@gimli:
        03BC.0000: PSH     {S0-FP, RA-RD}
        ...
@gimli_absorb_byte:
        04E9.0000: LDW     A2, [A0 + 0x30]
        ...
@gimli_squeeze_byte:
        04F8.0000: LDW     A1, [A0 + 0x30]
        ...
@gimli_advance:
        0503.0000: ADD     A1, A0, 0x30
        ...
@gimli_absorb:
        0522.0000: MOV     A2, A2
        ...
@gimli_squeeze:
        054B.0000: MOV     A2, A2
        ...
@gimli_pad:
        057E.0000: PSH     {A0, FP, RA-RD}
        ...
@gimli_hash_init:
        059F.0000: MOV     A1, ZERO
        ...
@gimli_hash_final:
        05C5.0000: PSH     {A0-A2, FP, RA-RD}
        ...
@gimli_hash:
        05D7.0000: PSH     {A0-A3, FP, RA-RD}
        ...
@memcmp8:
        0607.0000: MOV     A3, A0
        ...
@memcmp16:
        061D.0000: MOV     A3, A0
        ...
@memcmp:
        0633.0000: MOV     A2, A2
        ...
@read_line:
        0681.0000: MOV     A2, A0
        ...
@main:
        0764.0000: PSH     {S0, FP, RA-RD}
        ...
```

The executable includes symbols, so we can see the function names.

Given the frequent `gimli_*` function names, we can assume the hashing algorithm is [Gimli](https://en.wikipedia.org/wiki/Gimli_(cipher)).

One of `gimli_*` functions is `gimli_absorb_byte`; its name suggests it takes a byte when computing the hash of a byte sequence.

Before setting a breakpoint on the start of this function to see which bytes are passed, note the calling convention in the provided documentation: 

"*parameters are passed in registers `A0`-`A5`. Any additional arguments
are pushed to the stack in reverse order directly before calling the target function*"

Thus, one of the arguments to `gimli_absorb_byte` is likely a byte from secret code's byte sequence, because at some point the secret code will be hashed in order to display it when the `forgot` command sent.

```python
./runpeg AccessCode.peg --debug

EAR debugger
(dbg) b @gimli_absorb_byte
Created breakpoint #1 at address 04E9 (X)
(dbg) c
HW breakpoint #1 hit trying to execute 1 byte at 04E9

Thread state:
   (ZERO)R0: 0000      (S1)R8: FD97
     (A0)R1: 0A00      (S2)R9: 0004
     (A1)R2: 0073     (FP)R10: FD90
     (A2)R3: 0004     (SP)R11: FD8A
     (A3)R4: 0000     (RA)R12: 053B
     (A4)R5: 0000     (RD)R13: 0000
     (A5)R6: EA23     (PC)R14: 04E9 //@gimli_absorb_byte+0
     (S0)R7: 0A00    (DPC)R15: 0000

(dbg) c
HW breakpoint #1 hit trying to execute 1 byte at 04E9

Thread state:
   (ZERO)R0: 0000      (S1)R8: FD98
     (A0)R1: 0A00      (S2)R9: 0003
     (A1)R2: 0075     (FP)R10: FD90
     (A2)R3: 0001     (SP)R11: FD8A
     (A3)R4: 0073     (RA)R12: 053B
     (A4)R5: 0000     (RD)R13: 0000
     (A5)R6: EA23     (PC)R14: 04E9 //@gimli_absorb_byte+0
     (S0)R7: 0A00    (DPC)R15: 0000
```

Immediately after the executable starts (without even sending `forgot` command), it calls `gimli_absorb_byte`. Since we haven't provided any input yet, it's reasonable to assume the secret code is being hashed when the program is initialized.

We also notice that only one argument contained within the register `A1` changes between successive calls to `gimli_absorb_byte`. Therefore, `A1` register likely contains the byte of the secret code.

By repeatedly capturing each call to `gimli_absorb_byte`, we can extract every byte passed to the function and recover the secret code.

We captured the following bytes: `73 75 6E 7B 74 68 33 5F 66 75 6E 5F 70 34 72 37 5F 31 35 5F 6E 45 41 52 7D 01`

```bash
printf "\x73\x75\x6E\x7B\x74\x68\x33\x5F\x66\x75\x6E\x5F\x70\x34\x72\x37\x5F\x31\x35\x5F\x6E\x45\x41\x52\x7D"

sun{th3_fun_p4r7_15_nEAR}
```
