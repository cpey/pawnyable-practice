CC=/home/cpey/repos/musl/output/bin/musl-gcc

dexter-fine: dexter-fine.c
	$(CC) $< -o $@ -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f dexter-fine
