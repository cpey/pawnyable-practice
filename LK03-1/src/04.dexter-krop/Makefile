CC=/home/cpey/repos/musl/output/bin/musl-gcc

dexter-krop: dexter-krop.c
	$(CC) $< -o $@ -static -lpthread
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f dexter-krop
