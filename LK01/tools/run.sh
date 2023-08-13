#!/bin/sh

SMEP=1
SMAP=0
KASLR=0
KPTI=0

tools=$(realpath $(echo $0 | sed  "s/\(.*\)\(\/.*\)/\1/g"))
qemu=$tools/../qemu

[[ -n $1 ]] && rootfs=$1 || rootfs=$qemu/rootfs.cpio

# cpu configuration
cpu=qemu64
cmdline="console=ttyS0 loglevel=3 oops=panic panic=-1"
[[ $SMEP -eq 1 ]] && cpu=$cpu",+smep"
[[ $SMAP -eq 1 ]] && cpu=$cpu",+smap"
[[ $KASLR -eq 0 ]] && cmdline=$cmdline" nokaslr"
[[ $KPTI -eq 1 ]] && cmdline="$cmdline pti=on" || cmdline="$cmdline pti=off" 

kernel=$qemu/bzImage

qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel $kernel \
    -append "$cmdline" \
    -no-reboot \
    -cpu $cpu \
    -smp 1 \
    -monitor /dev/null \
    -initrd $rootfs \
    -net nic,model=virtio \
    -net user \
    -gdb tcp::12345
