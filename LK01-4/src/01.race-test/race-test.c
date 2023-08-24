#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

int win = 0;

void* race(void *arg) {
  while (1) {
    // Race until fd is 4 in any thread. Note that file descriptors are shared
    // among threads.
    while (!win) {
      int fd = open("/dev/holstein", O_RDWR);
      if (fd == 4) win = 1;
      if (win == 0 && fd != -1) close(fd);
    }

    // Confirm that the other thread did not close fd by accident
    if (write(3, "A", 1) != 1 || write(4, "a", 1) != 1) {
      // fail
      close(3);
      close(4);
      win = 0;
    } else {
      // success
      break;
    }
  }

  return NULL;
}

int main() {
  pthread_t th1, th2;

  pthread_create(&th1, NULL, race, NULL);
  pthread_create(&th2, NULL, race, NULL);
  pthread_join(th1, NULL);
  pthread_join(th2, NULL);

  char buf[0x400];
  int fd1 = 3, fd2 = 4;
  write(fd1, "Hello", 5);
  read(fd2, buf, 5);
  printf("%s\n", buf);

  return 0;
}
