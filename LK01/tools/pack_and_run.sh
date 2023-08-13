#!/bin/sh

# Example of use:
# $ ./tools/build_and_run.sh src/01.exploit/
set -ex
tools=$(realpath $(echo $0 | sed  "s/\(.*\)\(\/.*\)/\1/g"))

rootfs=$tools/../root
qemu=$tools/../qemu

pushd $(pwd)
cd $rootfs; find . -print0 | cpio -o --null --format=newc --owner=root > $qemu/debugfs.cpio 
popd
$tools/run.sh $qemu/debugfs.cpio
