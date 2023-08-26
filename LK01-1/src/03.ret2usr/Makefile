CC=/home/cpey/repos/musl/output/bin/musl-gcc

ret2usr: ret2usr.c
	$(CC) $< -o $@ -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f ret2usr
