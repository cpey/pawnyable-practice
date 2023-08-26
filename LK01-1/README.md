# Get root privileges

Extract rootfs:

~~~sh
[cpey@nuc rootfs]$ cpio -idv < ../qemu/rootfs_updated.cpio
.
media
sys
lib64
mnt
root
root/vuln.ko
...
~~~

Modify: 

~~~diff
--- original_fs/etc/init.d/S99pawnyable 2023-08-07 20:19:24.217834971 -0400
+++ root/etc/init.d/S99pawnyable        2023-08-07 20:09:12.010378496 -0400
@@ -9,7 +9,7 @@
 mount -vt devpts -o gid=4,mode=620 none /dev/pts
 chmod 666 /dev/ptmx
 stty -opost
-echo 2 > /proc/sys/kernel/kptr_restrict
+#echo 2 > /proc/sys/kernel/kptr_restrict
 #echo 1 > /proc/sys/kernel/dmesg_restrict

 ##
@@ -23,7 +23,7 @@
 ##
 echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
 echo "[ Holstein v1 (LK01) - Pawnyable ]"
-setsid cttyhack setuidgid 1337 sh
+setsid cttyhack setuidgid 0 sh

 ##
 ## Cleanup
~~~

Pack it back into a cpio:

~~~sh
[cpey@nuc rootfs]$ find . -print0 | cpio -o --format=newc --null --owner=root > ../qemu/rootfs_updated.cpio
3952 blocks
~~~

And launch the vm with the new rootfs:

~~~sh
[cpey@nuc qemu]$ ./run.sh rootfs_updated.cpio
Starting dhcpcd...
dhcpcd-9.4.0 starting
DUID 00:01:00:01:2c:64:45:13:52:54:00:12:34:56
eth0: IAID 00:12:34:56
eth0: soliciting an IPv6 router
eth0: soliciting a DHCP lease
eth0: offered 10.0.2.15 from 10.0.2.2
eth0: leased 10.0.2.15 for 86400 seconds
eth0: adding route to 10.0.2.0/24
eth0: adding default route via 10.0.2.2
forked to background, child pid 105

Boot took 5.14 seconds

[ Holstein v1 (LK01) - Pawnyable ]
/ #
~~~

# Calculating kernel symbol addresses

## Kernel module disassembly

_objdump_ shows the .text section at address 0x00, compared to 0x7c in _radare2_.

#### objdump

~~~sh
[cpey@nuc Holstein_module]$ objdump -D vuln.ko
...
Disassembly of section .text:

0000000000000000 <module_open>:
   0:   55                      push   %rbp
   1:   48 89 e5                mov    %rsp,%rbp
   4:   48 83 ec 20             sub    $0x20,%rsp
   8:   48 89 7d e8             mov    %rdi,-0x18(%rbp)
...
~~~

#### radare2

~~~sh
[0x0800007c]> is
[Symbols]
nth paddr      vaddr      bind   type   size lib name                         demangled
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
1   0x00000040 0x08000040 LOCAL  SECT   0        .note.gnu.build-id
2   0x00000064 0x08000064 LOCAL  SECT   0        .note.Linux
3   0x0000007c 0x0800007c LOCAL  SECT   0        .text
...
23  0x0000007c 0x0800007c LOCAL  FUNC   105      module_open
24  0x000000e5 0x080000e5 LOCAL  FUNC   183      module_read
25  0x0000019c 0x0800019c LOCAL  FUNC   239      module_write
26  0x0000028b 0x0800028b LOCAL  FUNC   50       module_close
27  0x00000500 0x08000500 LOCAL  OBJ    256      module_fops
~~~

## Calculating symbol addresses

The kernel module is loaded at the address given by `/proc/modules`. To find
the symbol address, we need to add the kernel load address (as given by
`/proc/modules`) to the physical address given by _radare2_ subtracted by
`.text` section physical addr.

As an example, given:

~~~sh
/ # cat /proc/modules
vuln 16384 0 - Live 0xffffffffc0000000 (O)
~~~~

`module_write` is found at 0xffffffffc0000120:

~~~sh
/ # grep module_write /proc/kallsyms
ffffffffc0000120 t module_write [vuln]
~~~

When using addresses given by _radare2_, we need to adjust by subtracting the
physical address of .text:

~~~sh
[0x0800007c]> ?  0xffffffffc0000000 + 0x0000019c - 0x0000007c
int64   -1073741536
uint64  18446744072635810080
hex     0xffffffffc0000120
~~~

This correction is not necessary when using _objdump_ or _ropr_.

# Finding ROP gadgets

Extract vmlinux [1]:

~~~sh
[cpey@nuc 04.smep]$ ./extract-vmlinux ../../qemu/bzImage > vmlinux
~~~

and look for gadgets:

~~~sh
[cpey@nuc 04.smep]$ ropr vmlinux --noisy --nosys --nojop -R 'pop rdi; ret;'
...
0xffffffff81cc6e66: pop rdi; ret;
~~~

The output address is an absolute address. This value is the base address
(0xffffffff81000000), when KASLR is disabled, plus the relative address, so in
the example above, 0xcc6e66 is the relative address.

`ropr` accepts regular expressions:

~~~sh
[cpey@nuc 04.smep]$ ropr vmlinux --noisy --nosys --nojop -R '^pop rdi.+ret;'
~~~

## Finding iretq

~~~sh
[cpey@nuc 04.smep]$ ropr vmlinux --noisy --nosys --nojop -R 'iretq'

==> Found 0 gadgets in 1.457 seconds
~~~

~~~sh
[cpey@nuc 04.krop]$ objdump -S -M intel vmlinux | grep iretq
ffffffff810202af:       48 cf                   iretq
...
~~~

[1] https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux
