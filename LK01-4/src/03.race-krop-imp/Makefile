CC=/home/cpey/repos/musl/output/bin/musl-gcc

race-krop-imp: race-krop-imp.c
	$(CC) $< -o $@ -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f race-krop-imp
