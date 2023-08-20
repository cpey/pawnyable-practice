CC=/home/cpey/repos/musl/output/bin/musl-gcc

stack_pivot: stack_pivot.c
	$(CC) $< -o $@ -static
	@# Necessary for the transfer script to pick the generated binary
	@echo $@ 

clean:
	rm -f stack_pivot
