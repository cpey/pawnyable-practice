#!/bin/sh

# Example of use:
# $ ./tools/pack_and_run.sh LK01/fs/rootfs_updated

set -ex
tools=$(realpath $(echo $0 | sed  "s/\(.*\)\(\/.*\)/\1/g"))

[[ -n $1 ]] && rootfs=$1 || (echo "Missing argument: specify the rootfs directory" && exit -1)
lk=$(echo $(realpath $1) | awk -F / '{print $(NF-2)}')
lk_dir=$tools/../$lk

qemu=$lk_dir/qemu

pushd $(pwd)
cd $rootfs; find . -print0 | cpio -o --null --format=newc --owner=root > $qemu/debugfs.cpio 
popd
$tools/run.sh -l $qemu/bzImage -r $qemu/debugfs.cpio
