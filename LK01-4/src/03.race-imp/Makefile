CC=/home/cpey/repos/musl/output/bin/musl-gcc

race-imp: race-imp.c
	$(CC) $< -o $@ -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f race-imp
