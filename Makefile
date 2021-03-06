# Radix Tree Makefile
# Josh Allmann <joshua.allmann@gmail.com>

all: test test-ipv6

CFLAGS=-g -DRADIXTREE_DEBUG -DLSB_FIRST
COMMON=radix.c radix.h
test: $(COMMON) test.c
	gcc $(CFLAGS) radix.c test.c -o $@

test-ipv6: $(COMMON)  test-ipv6.c
	gcc $(CFLAGS) radix.c test-ipv6.c -o $@

check: test-ipv6
	./test-ipv6

clean:
	rm -f test-ipv6 test *~
