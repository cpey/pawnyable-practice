CC=/home/cpey/repos/musl/output/bin/musl-gcc

poc:
	$(CC) poc.c -o poc -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f poc
