# User-After-Free

Practice from [1].

[1] https://pawnyable.cafe/linux-kernel/LK01/use_after_free.html

## Vulnerability 

The resources in the device driver are *shared* among all programs operating on
its file descriptor.

In the following example, the second call to `open` will replace `g_buf` with
the new allocation address. This is going to create a memory leak of the first
allocation.

~~~c
int fd1 = open( "/dev/holstein" , O_RDWR); 
int fd2 = open( "/dev/holstein" , O_RDWR); 
close(fd1); 
write(fd2, "Hello" , 5 );
~~~

`close` will free the second allocated address, and the following `write` will
result in an use-after-free (uaf).

## Exploiting UAF

The fake stack, will be set on a memory region that is used for a `tty_struct`
after the first uaf.

A second uaf `tty_struct` will be created to make its `->ops` member -- at
offset 0x18 -- point to the RIP (fake `tty_operations`), leaving enough space
to set the fake stack on the first object.

The exploit is trigger by calling the ioctl on the second uaf `tty_struct` object.
