CC=/home/cpey/repos/musl/output/bin/musl-gcc

control-rip: control-rip.c
	$(CC) $< -o $@ -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f control-rip
