# Pawnyable-Practice

Practice with the great
[*Pawnyable*](https://pawnyable.cafe/linux-kernel/index.html).

## Content

* Introduction: ret2usr, krop, kpti, and kaslr - [LK01-1](https://github.com/cpey/pawnyable/tree/main/LK01-1)
* Heap Overflow - [LK01-2](https://github.com/cpey/pawnyable/tree/main/LK01-2)
* Use-After-Free - [LK01-3](https://github.com/cpey/pawnyable/tree/main/LK01-3)
* Race Conditions - [LK01-4](https://github.com/cpey/pawnyable/tree/main/LK01-4)
* Null Pointer Dereference - [LK02](https://github.com/cpey/pawnyable/tree/main/LK02)
* Double Fetch - [LK03](https://github.com/cpey/pawnyable/tree/main/LK03)
* Using *userfaultfd* and *FUSE* - [LK04](https://github.com/cpey/pawnyable/tree/main/LK04)


## Running the Test System

Each top-level _LK*_ directory includes each own kernel and two versions of the
root filesystem in the *qemu* subfolder.

In order to test each exercise, it is necessary to extract each rootfs first.
As an example, extracting the root filesystems for the LK01-1 set of exercises,
can be done as follows:

~~~sh
$ ./tools/extract_rootfs.sh LK01-1/qemu/
~~~

Now a test environment can be launched including any of programs in LK01-1. As
an example, start the environment for
[LK01-1/src/01.test](https://github.com/cpey/pawnyable/tree/main/LK01-1/src/01.test),
doing:

~~~sh
$ ./tools/transfer.sh LK01-1/src/01-test
~~~

If willing to run with root access, modify the *ROOT* variable in
[*transfer.sh*](https://github.com/cpey/pawnyable/blob/main/tools/transfer.sh#L6)
before executing it.

## VM security configuration

Configuration of the security parameters of the VM, is set with the flags
[*SMEP*, *SMAP*, *KASLR*, and *KPTI*](https://github.com/cpey/pawnyable/blob/main/tools/run.sh#L6)
in run.sh.

The number of cores of the VM is adjusted in the same file using the
[SMP](https://github.com/cpey/pawnyable/blob/main/tools/run.sh#L13) variable.
