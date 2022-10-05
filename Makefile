# Je ne sais pas vraiment écrire des makefiles.

CCOPTS = -Werror -fPIC

all: serpent.so clean

serpent.so: serpent.o
	cc -shared -o $@ $<

serpent.o: serpent.c
	cc $(CCOPTS) -o serpent.o -c serpent.c

.PHONY: clean

clean:
	rm serpent.o

