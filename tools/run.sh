#!/bin/sh

# Use example:
# ./tools/run.sh -l LK01/qemu/bzImage -r LK01/qemu/rootfs_updated.cpio

# Configuration
SMEP=1
SMAP=0
KASLR=0
KPTI=0

# Arguments
# 1 - Linux kernel to run
# 2 (optional) - path of the rootfs
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -l|--linux)
            linux="$2"
            shift
            shift
            ;;
        -r|--rootfs)
            rootfs="$2"
            shift
            shift
            ;;
        *)
            echo "Unrecognized option: $key"
            exit 1
            ;;
    esac
done

[[ ! -n $linux ]] && echo "Missing argument '-l'" && exit -1

tools=$(realpath $(echo $0 | sed  "s/\(.*\)\(\/.*\)/\1/g"))
lk=$(echo $(realpath $linux) | awk -F / '{print $(NF-2)}')
qemu=$tools/../$lk/qemu

[[ ! -n $rootfs ]] && rootfs=$qemu/rootfs.cpio

# cpu configuration
cpu=qemu64
cmdline="console=ttyS0 loglevel=3 oops=panic panic=-1"
[[ $SMEP -eq 1 ]] && cpu=$cpu",+smep"
[[ $SMAP -eq 1 ]] && cpu=$cpu",+smap"
[[ $KASLR -eq 0 ]] && cmdline=$cmdline" nokaslr"
[[ $KPTI -eq 1 ]] && cmdline="$cmdline pti=on" || cmdline="$cmdline pti=off" 

kernel=$linux

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
