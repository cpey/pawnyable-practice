CC=/home/cpey/repos/musl/output/bin/musl-gcc

krop: krop.c
	$(CC) $< -o $@ -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f krop
