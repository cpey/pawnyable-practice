CC=gcc

fuse-test: fuse-test.c
	$(CC) $< -o $@ -static -I /usr/local/lib -D_FILE_OFFSET_BITS=64 -lpthread -lfuse
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f fuse-test
