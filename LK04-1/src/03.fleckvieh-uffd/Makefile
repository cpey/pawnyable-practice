CC=gcc

fleckvieh-uffd: fleckvieh-uffd.c
	$(CC) $< -o $@ -static -lpthread
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f fleckvieh-uffd
