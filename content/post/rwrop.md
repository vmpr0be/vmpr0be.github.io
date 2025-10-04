+++
author = "vmpr0be"
title = "rwROP - Control flow hijacking"
date = "2025-10-04"
categories = ["dev"]
+++

## Overview

rwROP stands for read/write ROP. This is nothing new, but I would like to shed some light on its potential. As the name suggests, it uses read and write primitives to achieve ROP easily without direct control of the stack.

This technique is especially useful when dealing with later versions of libc, which have many protections against function pointer hijacking.

While this is based on my observation, this technique appears to work on most LIBC versions, including the latest ones.

The technique's requirements are:
- 2x Arbitrary reads
- 1x Arbitrary write
- LIBC base address
- Main thread execution (we will come back to this)

This technique works as follows:
1. Leak the stack end address.
2. Calculate the return address offset.
3. Calculate the absolute return address using the offset and the stack leak.
4. Write the new return address and optional further stack variables.
5. Profit.

## Leakage

**There are better methods in order to leak the stack, but here we'll be focusing on __libc_stack_end**

`__libc_stack_end_ptr` is a pointer to `__libc_stack_end`, which stores the main thread's stack end address (the highest stack pointer value). This means that if you are trying to achieve control flow hijacking on a thread other than the main thread, this will not work.

To leak the stack, we first need the offset of the `__libc_stack_end_ptr` global variable located in libc's data section.

Using the already leaked LIBC base address, we calculate the absolute address of `__libc_stack_end_ptr` in memory: 

```python
__libc_stack_end_ptr = libc_base + __libc_stack_end_ptr_offset.
```

Then, we use the read primitive twice: first to read the value of `__libc_stack_end_ptr` (which is the address of `__libc_stack_end`), and then to read the contents of `__libc_stack_end` (which is the address of the stack end itself).

*An example of its usage in SunshineCTF 2025 (HeapX):*
```python
# arb_read_ptr is a wrapper that reads 8 bytes from memory and converts them to a 64-bit integer. Similarly, arb_write_ptr is a wrapper that writes a 64-bit integer as 8 bytes to memory.
# __libc_stack_end_ptr_offset: 0x20FE90

# Leak the stack end to calculate the address of the return address
stack_end_ptr = arb_read_ptr(libc.address + 0x20FE90) # Read the pointer to __libc_stack_end
stack_end = arb_read_ptr(stack_end_ptr) # Read the __libc_stack_end
log.info(f"Stack end: {hex(stack_end)}")
```

## Control

Since the stack grows downward, any return address is located at a fixed offset from the stack end. This means we can locate every return address if we know where the stack end is.

**The return address that is overwritten must be the next one used after the arbitrary write operation occurs.**

If the overwrite happens after the `RET` instruction has already used that return address to return to the caller, the technique will be useless.

You can optionally write variables (e.g., immediate values for POP instructions) to the stack for use in ROP chains.

*An example of its usage in SunshineCTF 2025 (HeapX):*
```python
# arb_write_ptr is a wrapper that writes a 64-bit integer as 8 bytes to memory.
# In this example, the stack_end - 0x148 is the address of the return address when the write operation happens, remember that this will be different on your side.
# he write operation itself will overwrite its own return address, thus causing execution to jump to our one_gadget.

# RA: Return Address
one_gadget = libc.address + 0xf72d2
RA_offset = 0x148
RA_address = stack_end - RA_offset

arb_write_ptr(RA_address, one_gadget)
```

### Notice
- Special thanks to ElChals for letting me know that this method isn't limited to `__libc_stack_end`; it can also be used with the `environ` global variable.
