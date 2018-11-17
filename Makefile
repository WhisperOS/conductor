CXXFLAGS =-std=c99 -pipe -g -Wall -Wextra -pedantic
CFLAGS  ?=
LDFLAGS  =
LIBS     = -lcrypto -lkrb5 -lcom_err -lldap -lgssapi_krb5 -lsasl2
PREFIX  ?= /usr/local
DESTDIR ?=

VERSION = $(shell git describe --tags | head -n1)
PACKAGE_URL = $(shell git config --get remote.origin.url | sed -e s/^git\@// -e "s/^github.com:/https:\/\/github.com\//" -e "s/\.git$$//" )

OBJS += src/utils.o src/log.o

BINS = conductor

conductor_OBJS := src/conductor.h $(OBJS) src/parse.o src/scanner.o src/conductor.o src/main.o

all: $(BINS)

define BIN_template =
 $(1): $$($(1)_OBJS) $$($(1)_LIBS:%=-l%)
 ALL_OBJS   += $$($(1)_OBJS)
endef

$(foreach bin,$(BINS),$(eval $(call BIN_template,$(bin))))

$(BINS):
	$(CC) $(CFLAGS) $(LIBS) $(LDFLAGS) -o $@ ${$@_OBJS}

src/scanner.c: src/scanner.l src/parse.c
	$(LEX) --header-file --yylineno --outfile=$@ $<
src/parse.c: src/parse.y
	$(YACC) -d --output-file=src/parse.c $<
src/%.o: src/%.c
	$(CC) -c -o $@ $(CFLAGS) $(CXXFLAGS) $<

src/%.h: src/%.h.in
	sed -e 's/@VERSION@/$(VERSION)/g' \
		-e 's$$@PACKAGE_URL@$$$(PACKAGE_URL)$$g' $< > $@

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
	rm -f $(BINS) src/conductor.h src/*.o src/parse.[ch] src/scanner.c
	rm -f *.pem man/conductor.1 man/conductor-schema.ldif
	rm -rf man/ldif
