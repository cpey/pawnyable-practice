CC=gcc

fleckvieh-fuse: fleckvieh-fuse.c
	$(CC) $< -o $@ -static -I /usr/local/lib -D_FILE_OFFSET_BITS=64 -lpthread -lfuse
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f fleckvieh-fuse
