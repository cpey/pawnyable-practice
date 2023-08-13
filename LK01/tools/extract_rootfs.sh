#!/bin/sh

tools=$(realpath $(echo $0 | sed  "s/\(.*\)\(\/.*\)/\1/g"))
root=$tools/../
qemu=$root/qemu

rootfs=$qemu/rootfs.cpio

orig_dir=fs/rootfs_original
upd_dir=fs/rootfs_updated

pushd $(pwd)

mkdir -p $orig_dir
mkdir -p $upd_dir

cd $root/$orig_dir
cpio -idv < $qemu/rootfs.cpio

cd $root/$upd_dir
cpio -idv < $qemu/rootfs_updated.cpio

popd
