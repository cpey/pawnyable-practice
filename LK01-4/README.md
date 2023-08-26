# Race Condition

Practice from [1].

[1] https://pawnyable.cafe/linux-kernel/LK01/race_condition.html

## Race condition in module_open()

When multiple processes are accessing `module_open()`, there is the
possibility of a context switch right after the check and before the assignment
`mutex = 1` that allows the two threads to allocate `g_buf`.

The race condition exists by not using an atomic operation to read and write
the mutex variable, which results in a data race on the `g_buf` pointer.

Winning the race will result in the same use-after-free vulnerability seen in
[part 3](https://github.com/cpey/pawnyable/tree/main/LK01-3).

~~~gdb
[0x08000199 [xAdvc]0 2% 245 vuln.ko]> pd $r @ sym.module_open
┌ 107: sym.module_open ();
│           0x08000199      55             push rbp
│           0x0800019a      4889e5         mov rbp, rsp
│           0x0800019d      53             push rbx
│           0x0800019e      48c7c7000000.  mov rdi, 0                  ; RELOC 32 .rodata.str1.1 @ 0x080002ba + 0x8b
│           0x080001a5      e800000000     call _printk                ;[1]; RELOC 32 _printk
│           ; CALL XREF from sym.module_open @ 0x80001a5(x)
│           0x080001aa      8b1d00000000   mov ebx, dword [0x080001b0]    ; [0x80001b0:4]=0x1674db85; RELOC 32 mutex @ 0x08000848 - 0x80001b0
│           ; DATA XREF from sym.module_open @ 0x80001aa(r)
│           0x080001b0      85db           test ebx, ebx
│       ┌─< 0x080001b2      7416           je 0x80001ca
│       │   0x080001b4      48c7c7000000.  mov rdi, 0                  ; RELOC 32 .rodata.str1.1 @ 0x080002ba + 0xa1
│       │   0x080001bb      e800000000     call _printk                ;[2]; RELOC 32 _printk
│       │   ; CALL XREF from sym.module_open @ 0x80001bb(x)
│       │   0x080001c0      bbf0ffffff     mov ebx, 0xfffffff0         ; 4294967280
│       │   ; CODE XREFS from sym.module_open @ 0x80001ef(x), 0x8000202(x)
│     ┌┌──> 0x080001c5      89d8           mov eax, ebx
│     ╎╎│   0x080001c7      5b             pop rbx
│     ╎╎│   0x080001c8      5d             pop rbp
│     ╎╎│   0x080001c9      c3             ret
│     ╎╎│   ; CODE XREF from sym.module_open @ 0x80001b2(x)
│     ╎╎└─> 0x080001ca      c70500000000.  mov dword [0x080001d4], 1    ; [0x80001d3:4]=0xdc0be00; RELOC 32 mutex @ 0x08000848 - 0x80001d4
│     ╎╎    0x080001d4      bec00d0000     mov esi, 0xdc0              ; 3520
│     ╎╎    0x080001d9      488b3d000000.  mov rdi, qword [0x080001e0]    ; [0x80001e0:8]=0x5894800000000e8; RELOC 32 kmalloc_caches
│     ╎╎    ; DATA XREF from sym.module_open @ 0x80001d9(r)
│     ╎╎    0x080001e0      e800000000     call kmem_cache_alloc       ;[3]; RELOC 32 kmem_cache_alloc
│     ╎╎    ; CALL XREF from sym.module_open @ 0x80001e0(x)
│     ╎╎    0x080001e5      488905000000.  mov qword [0x080001ec], rax    ; [0x80001eb:8]=0xc748d475c0854800; RELOC 32 g_buf @ 0x08000840 - 0x80001ec
│     ╎╎    0x080001ec      4885c0         test rax, rax
│     └───< 0x080001ef      75d4           jne 0x80001c5
│      ╎    0x080001f1      48c7c7000000.  mov rdi, 0                  ; RELOC 32 .rodata.str1.1 @ 0x080002ba + 0xb4
│      ╎    0x080001f8      e800000000     call _printk                ;[4]; RELOC 32 _printk
│      ╎    ; CALL XREF from sym.module_open @ 0x80001f8(x)
│      ╎    0x080001fd      bbf4ffffff     mov ebx, 0xfffffff4         ; 4294967284
└      └──< 0x08000202      ebc1           jmp 0x80001c5
> is~mutex
43  0x00000848 0x08000848 GLOBAL OBJ    4        mutex
~~~

A test of the race condition can be found in [src/01.race-test/race-test.c](https://github.com/cpey/pawnyable/blob/main/LK01-4/src/01.race-test/race-test.c)

## CPU and Heap Spray

The SLUB allocator manages the slab used for object allocation in a memory area dedicated to each CPU core. That has to be kept into consideration when running the heap spray.

Using `sched_setaffinity(2)` we can define the CPU a given thread is assigned.

- Find exploit in [src/02.race-krop/race-krop.c](https://github.com/cpey/pawnyable/blob/main/LK01-4/src/02.race-krop/race-krop.c)
and a more reliable version in [src/03.race-imp/race-imp.c](https://github.com/cpey/pawnyable/blob/main/LK01-4/src/03.race-imp/race-imp.c)
- Version found in [src/08.race-scan/race-scan.c](https://github.com/cpey/pawnyable/blob/main/LK01-4/src/08.race-scan/race-scan.c) adjusts the exploit to the number of CPUs

## Key Points

- The CPU core that performed the memory allocation in kernel space is not necessarily related to the CPU cores used during the race.
- The spray needs to be done on the same CPU that performed the allocation.

