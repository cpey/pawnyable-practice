# NULL Pointer Dereference

Practice from [1].

[1] https://pawnyable.cafe/linux-kernel/LK02/null_ptr_deref.html


## mmap_min_addr

*mmap_min_addr* limits the lowest address that can be mapped from userland. It
is a non-zero value by default, but is set to 0 in our target.

~~~sh
/ $ cat /proc/sys/vm/mmap_min_addr
0
~~~

This chapter attacks work only when SMAP and *mmap_min_addr* security mechanims
are not present.

