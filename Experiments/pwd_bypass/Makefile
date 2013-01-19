CC=gcc
CFLAGS=-g -fno-stack-protector

pwd: pwd.c
	$(CC) $(CFLAGS) pwd.c -o pwd

.PHONY: clean
clean:
	rm -f pwd
