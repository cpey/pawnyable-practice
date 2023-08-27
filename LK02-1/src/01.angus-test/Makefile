CC=/home/cpey/repos/musl/output/bin/musl-gcc

angus-test: angus-test.c
	$(CC) $< -o $@ -static -lpthread
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f angus-test
