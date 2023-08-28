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
