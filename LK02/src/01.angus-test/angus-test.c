#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>

#define CMD_INIT    0x13370001
#define CMD_SETKEY  0x13370002
#define CMD_SETDATA 0x13370003
#define CMD_GETDATA 0x13370004
#define CMD_ENCRYPT 0x13370005
#define CMD_DECRYPT 0x13370006

struct XorCipher {
  char *key;
  char *data;
  size_t keylen;
  size_t datalen;
};

struct request {
  char *ptr;
  size_t len;
};

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int main() {
  int fd = open("/dev/angus", O_RDWR);
  if (fd == -1) fatal("open");

  struct request r;
  ioctl(fd, CMD_ENCRYPT, &r);
}
