CC=/home/cpey/repos/musl/output/bin/musl-gcc

fleckvieh-race: fleckvieh-race.c
	$(CC) $< -o $@ -static -lpthread
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f fleckvieh-race
