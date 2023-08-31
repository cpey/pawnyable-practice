# Using userfaultfd

Practice from [1].

[1] https://pawnyable.cafe/linux-kernel/LK04/uffd.html

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

A [race test](https://github.com/cpey/pawnyable/blob/main/LK04-1/src/01.fleckvieh-race/fleckvieh-race.c)
quickly results in a kernel [crash](https://github.com/cpey/pawnyable/blob/main/LK04-1/src/01.fleckvieh-race/crashdump).
