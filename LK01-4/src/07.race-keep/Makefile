CC=/home/cpey/repos/musl/output/bin/musl-gcc

race-keep: race-keep.c
	$(CC) $< -o $@ -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f race-keep
