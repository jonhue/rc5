CFLAGS=-g -O2 -Wall -pedantic

.PHONY: all
all: rc5

rc5: rc5.c rc5.h rc5.S -lbsd

.PHONY: clean
clean:
	rm -f rc5
