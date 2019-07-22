CFLAGS=-g -O2 -Wall -Wextra -pedantic -Wunused -Wrestrict

.PHONY: all
all: rc5 enlighten

rc5: rc5.c rc5.h rc5.S bufferio.o
	$(CC) $(CFLAGS) -o $@ $^ -lbsd

enlighten: enlighten.c bufferio.o
	$(CC) $(CFLAGS) -o $@ $^

bufferio.o: bufferio.c bufferio.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f rc5 enlighten bufferio.o
