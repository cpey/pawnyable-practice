CC=gcc

fleckvieh-uaf: fleckvieh-uaf.c
	$(CC) $< -o $@ -static -lpthread
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f fleckvieh-uaf
