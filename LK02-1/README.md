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

## struct file

File descriptors are used when manipulating drivers from user space, but
they are received as `struct file` on the kernel side.

The *file* structure has file-specific information, such as the cursor
position. It has a member that kernel modules are free to use:
`private_data`.

~~~c
File: include/linux/fs.h

struct file {
        union {
                struct llist_node       fu_llist;
                struct rcu_head         fu_rcuhead;
        } f_u;
        struct path             f_path;
        struct inode            *f_inode;       /* cached value */
        const struct file_operations    *f_op;

        /*
         * Protects f_ep_links, f_flags.
         * Must not be taken from IRQ context.
         */
        spinlock_t              f_lock;
        enum rw_hint            f_write_hint;
        atomic_long_t           f_count;
        unsigned int            f_flags;
        fmode_t                 f_mode;
        struct mutex            f_pos_lock;
        loff_t                  f_pos;
        struct fown_struct      f_owner;
        const struct cred       *f_cred;
        struct file_ra_state    f_ra;

        u64                     f_version;
#ifdef CONFIG_SECURITY
        void                    *f_security;
#endif
        /* needed for tty driver, and maybe others */
        void                    *private_data;

#ifdef CONFIG_EPOLL
        /* Used by fs/eventpoll.c to link all the hooks to this file */
        struct list_head        f_ep_links;
        struct list_head        f_tfile_llink;
#endif /* #ifdef CONFIG_EPOLL */
        struct address_space    *f_mapping;
        errseq_t                f_wb_err;
} __randomize_layout
~~~

> NOTE: If data was stored there in LK01 modules, there would be no conflicts.

## Vulnerability

`xor()` accesses `ctx` without checking it is not NULL, neither does its caller `module_ioctl()`:

~~~c
long xor(XorCipher *ctx) {
  size_t i;

  if (!ctx->data || !ctx->key) return -EINVAL;
  for (i = 0; i < ctx->datalen; i++)
    ctx->data[i] ^= ctx->key[i % ctx->keylen];
  return 0;
}

static long module_ioctl(struct file *filp,
                         unsigned int cmd,
                         unsigned long arg) {
  request_t req;
  XorCipher *ctx;

  if (copy_from_user(&req, (void*)arg, sizeof(request_t)))
    return -EINVAL;

  ctx = (XorCipher*)filp->private_data;

  switch (cmd) {
...
    case CMD_ENCRYPT:
    case CMD_DECRYPT:
      return xor(ctx);
...
~~~

Find test program and crashdump in:
- [src/01.angus-test/angus-test.c](https://github.com/cpey/pawnyable/blob/main/LK02-1/src/01.angus-test/angus-test.c)
- [src/01.angus-test/crashdump](https://github.com/cpey/pawnyable/blob/main/LK02-1/src/01.angus-test/crashdump)
