Disassembly of: 
~~~
/ # cat /proc/kallsyms | grep swapgs_restore_regs_and_return_to_usermode
ffffffff81800e10 T swapgs_restore_regs_and_return_to_usermode
~~~

~~~gdb
pwndbg> x/40i $rip
=> 0xffffffff81800e10:  pop    r15
   0xffffffff81800e12:  pop    r14
   0xffffffff81800e14:  pop    r13
   0xffffffff81800e16:  pop    r12
   0xffffffff81800e18:  pop    rbp
   0xffffffff81800e19:  pop    rbx
   0xffffffff81800e1a:  pop    r11
   0xffffffff81800e1c:  pop    r10
   0xffffffff81800e1e:  pop    r9
   0xffffffff81800e20:  pop    r8
   0xffffffff81800e22:  pop    rax
   0xffffffff81800e23:  pop    rcx
   0xffffffff81800e24:  pop    rdx
   0xffffffff81800e25:  pop    rsi
   0xffffffff81800e26:  mov    rdi,rsp                 <--- ROP here
   0xffffffff81800e29:  mov    rsp,QWORD PTR gs:0x6004
   0xffffffff81800e32:  push   QWORD PTR [rdi+0x30]
   0xffffffff81800e35:  push   QWORD PTR [rdi+0x28]
   0xffffffff81800e38:  push   QWORD PTR [rdi+0x20]
   0xffffffff81800e3b:  push   QWORD PTR [rdi+0x18]
   0xffffffff81800e3e:  push   QWORD PTR [rdi+0x10]
   0xffffffff81800e41:  push   QWORD PTR [rdi]
   0xffffffff81800e43:  push   rax
   0xffffffff81800e44:  xchg   ax,ax
   0xffffffff81800e46:  mov    rdi,cr3
   0xffffffff81800e49:  jmp    0xffffffff81800e7f
...

pwndbg> x/10i 0xffffffff81800e7f
   0xffffffff81800e7f:  or     rdi,0x1000
   0xffffffff81800e86:  mov    cr3,rdi
   0xffffffff81800e89:  pop    rax
   0xffffffff81800e8a:  pop    rdi
   0xffffffff81800e8b:  swapgs
   0xffffffff81800e8e:  jmp    0xffffffff81800eb0
...

pwndbg> x/10i 0xffffffff81800eb0
   0xffffffff81800eb0:  test   BYTE PTR [rsp+0x20],0x4
   0xffffffff81800eb5:  jne    0xffffffff81800eb9
   0xffffffff81800eb7:  iretq
...
~~
