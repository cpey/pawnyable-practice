CC=/home/cpey/repos/musl/output/bin/musl-gcc

uaf-stack-pivot: uaf-stack-pivot.c
	$(CC) $< -o $@ -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f uaf-stack-pivot
