CXXFLAGS =-std=c99 -pipe -g -Wall -Wextra -pedantic
CFLAGS  ?=
LDFLAGS  =
LIBS     = -lcrypto
PREFIX  ?= /usr/local
DESTDIR ?=

all: conductor

conductor: src/main.o
	$(CC) -o $@ $(LIBS) $(CFLAGS) $(CXXFLAGS) $(LDFLAGS) $^

src/%.o: src/%.c
	$(CC) -c -o $@ $(CFLAGS) $(CXXFLAGS) $<

man/%: man/%.pod
	pod2man $< > $@

doc: man/conductor.1

install: conductor doc
	strip conductor
	install -m 0755 -D conductor $(DESTDIR)$(PREFIX)/bin/conductor
	gzip man/conductor.1 -c > conductor.1.gz
	install -m 0644 -D conductor.1.gz $(DESTDIR)$(PREFIX)/share/man/man1/conductor.1.gz
	rm conductor.1.gz

clean:
	rm -f conductor *.o
	rm -f *.pem
