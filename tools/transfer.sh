#!/bin/sh

# Example of use:
# $ ./tools/transfer.sh LK01/src/01.test/

ROOT=0

set -ex
tools=$(realpath $(echo $0 | sed  "s/\(.*\)\(\/.*\)/\1/g"))

[[ -n $1 ]] && src=$1 || (echo "Missing argument: specify the source code directory" && exit -1)
lk=$(echo $(realpath $1) | awk -F / '{print $(NF-2)}')
lk_dir=$tools/../$lk
fs_dir=$lk_dir/fs
[[ ! -d $fs_dir ]] && echo "Error: run ./tools/extract_rootfs.sh" && exit -1

[[ $ROOT -eq 1 ]] && fs=rootfs_updated || fs=rootfs_original

rootfs=$fs_dir/$fs
qemu=$lk_dir/qemu

dest=$rootfs
[[ -n $2 ]] && dest=$dest/$2

pushd $(pwd)
cd $src
make clean
bin=$(make | tail -1)
mv $bin $dest
cd $rootfs; find . -print0 | cpio -o --null --format=newc --owner=root > $qemu/debugfs.cpio 
popd
$tools/run.sh -l $lk/qemu/bzImage -r $qemu/debugfs.cpio
