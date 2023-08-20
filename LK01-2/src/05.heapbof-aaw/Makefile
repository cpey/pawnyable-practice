CC=/home/cpey/repos/musl/output/bin/musl-gcc

heapbof-aaw: heapbof-aaw.c
	$(CC) $< -o $@ -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f heapbof-aaw
