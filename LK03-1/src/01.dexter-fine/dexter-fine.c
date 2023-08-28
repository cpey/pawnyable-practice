/**
 * Fine use of the dexter module
 * 
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define CMD_GET 0xdec50001
#define CMD_SET 0xdec50002

typedef struct {
  char *ptr;
  size_t len;
} request_t;

int fd;

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int set(char *buf, size_t len) {
  request_t req = { .ptr=buf, .len=len };
  return ioctl(fd, CMD_SET, &req);
}

int get(char *buf, size_t len) {
  request_t req = { .ptr=buf, .len=len };
  return ioctl(fd, CMD_GET, &req);
}

int main() {
  fd = open("/dev/dexter", O_RDWR);
  if (fd == -1) fatal("/dev/dexter");

  char buf[0x20];
  set("Hello, World!", 13);
  get(buf, 13);
  printf("%s\n", buf);

  close(fd);
  return 0;
}
