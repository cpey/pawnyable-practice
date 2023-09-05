CC=/home/cpey/repos/musl/output/bin/musl-gcc

dexter-oob: dexter-oob.c
	$(CC) $< -o $@ -static -lpthread
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f dexter-oob
