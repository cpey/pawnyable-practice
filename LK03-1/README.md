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


