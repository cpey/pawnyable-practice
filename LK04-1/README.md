# Using userfaultfd and FUSE

Practice from [1] and [2].

[1] https://pawnyable.cafe/linux-kernel/LK04/uffd.html
[2] https://pawnyable.cafe/linux-kernel/LK04/fuse.html

## Vulnerability

The vulnerability is due to the data race that exists since no locks are being
held while manipulating the list.

This time, the race contenders will be using the same file descriptor in
order to operate on the same list. Note that this is different from the
exploitation of the [Holstein
wodule](https://github.com/cpey/pawnyable/blob/main/LK01-4/src/Holstein_module_v4/vuln.c),
in which each contender in the race had to open a new file descriptor.

## Exploitation Challenge

Since the data is handled in a bidirectional list, trying to read or write
data at the same time of a delete, may cause the read or write to happen while
the unlinking of the object to be deleted. This may result in corrupting the
state of the link and kernel memory.

A [race
test](https://github.com/cpey/pawnyable/blob/main/LK04-1/src/01.fleckvieh-race/fleckvieh-race.c)
adding and deleting data, quickly results in a kernel
[crash](https://github.com/cpey/pawnyable/blob/main/LK04-1/src/01.fleckvieh-race/crashdump).

## userfaultfd

System call that allows to delegate page-fault handling to a user-space
application. It is added to the kernel with the built config *CONFIG_USERFAULTFD*.

It requires the caller to be privileged (does have CAP_SYS_PTRACE capability in
the initial user namespace), or */proc/sys/vm/unprivileged_userfaultfd* has the
value 1 (sysctl knob vm.unprivileged_userfaultfd).

`userfaultfd(2)` creates a new userfaultfd object that is returned as a file
descriptor. It is configured using `ioctl(2)`. Once configured, the application
can use `read(2)` to received its notifications.

When a page fault occurs, the registered userspace handler is called. The
thread trying to read the page blocks until the handler returns the data.
This way, kernel space processing can be stopped at the time of reading and
writing to memory.

The userfaultfd
[example](https://github.com/cpey/pawnyable/blob/main/LK04-1/src/02.uffd-test/uffd-test.c)
allocates 2 pages of memory for which to set the page fault handler. The
userfaultfd handler fires on the first access to each page.

> NOTE: Keep in mind that since the handler runs on a separate thread, we need
> to fix the CPU with the sched_setaffinity if we are going to spray from
> within it.

## Exploitation

### UAF Read 

Uses `blob_get()`. Makes it cause a page fault at the time of executing
_copy_to_user()_. In the page fault handler, the victim is deleted and
_tty_struct_ objects are sprayed. The fault handler exits and `blob_get()` ends
up returning the _tty_struct_ that is now found at the position of the deleted
object.

* A poc of the uaf in 
[fleckvieh-uaf.c](https://github.com/cpey/pawnyable/blob/main/LK04-1/src/03.fleckvieh-uaf/fleckvieh-uaf.c)

### UAF Write 

Uses `blob_set()`. Makes it cause a page fault at the time of executing
_copy_from_user()_. In the page fault handler, the victim is deleted and
_tty_struct_ objects are sprayed. The handler fills the _src_ address with the
content to overwrite _tty_struct_ with. The fault handler exits and
`blob_set()` finishes overwritting the victim, now a _tty_struct_,  with the
fake _tty_struct_ content.

* Final exploit in 
[fleckvieh-uffd.c](https://github.com/cpey/pawnyable/blob/main/LK04-1/src/04.fleckvieh-uffd/fleckvieh-uffd.c)

# FUSE

Filesystem in Userspace (FUSE) is added to the kernel with the built config *CONFIG_FUSE_FS*.

## Configuring libfuse in the local system

Download [libuse](https://github.com/libfuse/libfuse), checkout to branch
*fuse-2.9.9* and apply the
[patch](https://github.com/libfuse/libfuse/commit/5a43d0f724c56f8836f3f92411e0de1b5f82db32)
before building:

~~~sh
git clone https://github.com/libfuse/libfuse.git
cd libfuse
git checkout fuse-2.9.9
git cherry-pick 5a43d0f724c56f8836f3f92411e0de1b5f82db32
./makeconf.sh
configure --enable-static=yes
make-j8
make install
~~~

After building, static and shared libraries for libfuse v2.9.9 are found in */usr/local/lib*:

~~~sh
$ ls /usr/local/lib/libfuse.* -1
/usr/local/lib/libfuse.a
/usr/local/lib/libfuse.la
/usr/local/lib/libfuse.so
/usr/local/lib/libfuse.so.2
/usr/local/lib/libfuse.so.2.9.9
~~~

Now we can build and run the [test
program](https://github.com/cpey/pawnyable/blob/main/LK04-1/src/05.fuse-test/fuse-test.cffd.c)
on the test system.

~~~sh
~ $ mkdir /tmp/test
~ $ ./fuse-test /tmp/test
~ $ ls -tlra /tmp/test/file
[+] getattr_callback
-rwxrwxrwx    1 root     root            14 Jan  1  1970 /tmp/test/file
~ $ cat /tmp/test/file
[+] getattr_callback
[+] open_callback
[+] read_callback
Hello, World!
~~~

