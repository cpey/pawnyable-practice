#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

void  fatal(const char *msg) { 
	perror(msg);
	exit (1);
}

int  main () {
	int fd = open("/dev/holstein" , O_RDWR);
	if (fd == -1) fatal("open(\"/dev/holstein\")");

  	char buf[0x100] = {};
  	write(fd, "Hello, World!", 13);
  	read(fd, buf, 0x100);
  	printf ("Data: %s\n", buf);
	close (fd); 

	return 0;
}
