CC=/home/cpey/repos/musl/output/bin/musl-gcc

uaf-aaw-poweroff: uaf-aaw-poweroff.c
	$(CC) $< -o $@ -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f uaf-aaw-poweroff
