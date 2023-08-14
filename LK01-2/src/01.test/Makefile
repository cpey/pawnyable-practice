CC=/home/cpey/repos/musl/output/bin/musl-gcc

test:
	$(CC) test.c -o test -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f test
