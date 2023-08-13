#!/bin/sh

# Example:
# ./tools/extract_rootfs.sh LK01/qemu/

if [[ -n $1 ]]; then
    src=$1
else
    echo "Missing argument: specify directory containing the root filesystems"
    exit -1
fi

lk=$(echo $(realpath $1) | awk -F / '{print $(NF-1)}')
tools=$(realpath $(echo $0 | sed  "s/\(.*\)\(\/.*\)/\1/g"))
lk_dir=$tools/../$lk
fs_dir=$lk_dir/fs
qemu=$lk_dir/qemu
rootfs=$qemu/rootfs.cpio

orig_dir=$fs_dir/rootfs_original
upd_dir=$fs_dir/rootfs_updated

pushd $(pwd)

mkdir -p $orig_dir
mkdir -p $upd_dir

cd $orig_dir
cpio -idv < $qemu/rootfs.cpio

cd $upd_dir
cpio -idv < $qemu/rootfs_updated.cpio

popd
