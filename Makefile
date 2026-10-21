CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror

all: libraw.so

libraw.so: native.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $<

test:
	python3 -m unittest discover -s tests -v

clean:
	rm -f libraw.so

.PHONY: all test clean
