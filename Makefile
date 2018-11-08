CXXFLAGS =-std=c99 -pipe -g -Wall -Wextra -pedantic
CFLAGS  ?=
LDFLAGS  =
LIBS     = -lcrypto
PREFIX  ?= /usr/local
DESTDIR ?=
VERSION = $(shell git describe --tags | head -n1)

all: conductor

conductor: src/main.o
	$(CC) -o $@ $(LIBS) $(CFLAGS) $(CXXFLAGS) $(LDFLAGS) $^

src/%.o: src/%.c
	$(CC) -c -o $@ $(CFLAGS) $(CXXFLAGS) $<


schema:
	rm -rf man/ldif
	mkdir -p man/ldif
	@echo "include /etc/openldap/schema/core.schema" > man/schema-convert.conf
	@echo "include $(PWD)/man/conductor.schema" >> man/schema-convert.conf
	slaptest -f man/schema-convert.conf -F man/ldif
	cp man/ldif/cn=config/cn=schema/cn={1}conductor.ldif man/conductor-schema.ldif
	sed -e '/entryUUID/d' -e '/creatorsName/d' \
		-e '/modifyTimestamp/d' -e '/createTimestamp/d' \
		-e '/modifiersName/d' -e '/^#/d' -e '/entryCSN/d' \
		-e 's/{1}conductor/conductor/' \
		-e 's/^dn:\ .*/dn:\ cn=conductor,cn=schema,cn=config/' \
		-i man/conductor-schema.ldif

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
	rm -f conductor *.o src/*.o
	rm -f *.pem
