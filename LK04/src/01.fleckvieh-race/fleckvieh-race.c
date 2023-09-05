#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

int fd;

#define CMD_ADD 0xf1ec0001
#define CMD_DEL 0xf1ec0002
#define CMD_GET 0xf1ec0003
#define CMD_SET 0xf1ec0004

typedef struct {
  int id;
  size_t size;
  char *data;
} request_t;

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int add(char *data, size_t size) {
  request_t req = { .size = size, .data = data };
  return ioctl(fd, CMD_ADD, &req);
}
int del(int id) {
  request_t req = { .id = id };
  return ioctl(fd, CMD_DEL, &req);
}
int get(int id, char *data, size_t size) {
  request_t req = { .id = id, .size = size, .data = data };
  return ioctl(fd, CMD_GET, &req);
}
int set(int id, char *data, size_t size) {
  request_t req = { .id = id, .size = size, .data = data };
  return ioctl(fd, CMD_SET, &req);
}

int race_win;

void *race(void *arg) {
  int id;
  while (!race_win) {
    id = add("Hello", 6);
    del(id);
  }
}

int main() {
  fd = open("/dev/fleckvieh", O_RDWR);
  if (fd == -1) fatal("/dev/fleckvieh");

  race_win = 0;

  pthread_t th;
  pthread_create(&th, NULL, race, NULL);

  int id;
  for (int i = 0; i < 0x1000; i++) {
    id = add("Hello", 6);
    del(id);
  }
  race_win = 1;
  pthread_join(th, NULL);

  close(fd);
  return 0;
}
