#!/bin/sh

# Example of use:
# $ ./tools/transfer.sh src/01.exploit/

ROOT=1

set -ex
tools=$(realpath $(echo $0 | sed  "s/\(.*\)\(\/.*\)/\1/g"))

fs_dir=$tools/../fs
[[ ! -d $fs_dir ]] && echo "Error: run ./tools/extract_rootfs.sh" && exit -1

[[ $ROOT -eq 1 ]] && fs=rootfs_updated || fs=rootfs_original

rootfs=$fs_dir/$fs
qemu=$tools/../qemu

[[ -n $1 ]] && src=$1 || (echo "Missing argument: specify the source code directory" && exit -1)

dest=$rootfs
[[ -n $2 ]] && dest=$dest/$2

pushd $(pwd)
cd $src
make clean
bin=$(make | tail -1)
mv $bin $dest
cd $rootfs; find . -print0 | cpio -o --null --format=newc --owner=root > $qemu/debugfs.cpio 
popd
$tools/run.sh $qemu/debugfs.cpio
