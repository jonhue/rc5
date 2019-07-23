CFLAGS=-g -O2 -Wall -Wextra -pedantic -Wunused -Wrestrict

.PHONY: all
all: rc5 enlighten key_expansion

rc5: rc5.c rc5.h rc5.S test.h test.c references/rfc2040.h references/rfc2040.c bufferio.o
	$(CC) $(CFLAGS) -o $@ $^ -lbsd

enlighten: enlighten.c bufferio.o
	$(CC) $(CFLAGS) -o $@ $^

bufferio.o: bufferio.c bufferio.h
	$(CC) $(CFLAGS) -c -o $@ $<

key_expansion: key_expansion.c key_expansion.S rc5.h
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f rc5 enlighten bufferio.o key_expansion
