AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I macros

CLEANFILES = *.a *.h *.o *.so *.slo *.lo *.la *.h *.dylib

if LINUX
SHARED_EXT=so
endif
if OSX
SHARED_EXT=dylib
endif

all: coraza/coraza.h libcoraza.a libcoraza.$(SHARED_EXT)

coraza/coraza.h: libcoraza/coraza.go libcoraza/log.go libcoraza/fs.go
	@mkdir -p coraza
	go tool cgo -exportheader $@ $^

libcoraza.a: libcoraza/coraza.go libcoraza/log.go libcoraza/fs.go
	go build -buildmode=c-archive -o $@ $^

libcoraza.$(SHARED_EXT): libcoraza/coraza.go libcoraza/log.go libcoraza/fs.go
	go build -buildmode=c-shared -o $@ $^

install-data-local: all check
	@INSTALL@ -d $(DESTDIR)@prefix@/lib
	@INSTALL@ -d $(DESTDIR)@prefix@/include/coraza
	@INSTALL@ libcoraza.a $(DESTDIR)@prefix@/lib/
	@INSTALL@ libcoraza.$(SHARED_EXT) $(DESTDIR)@prefix@/lib/
	@INSTALL@ coraza/coraza.h $(DESTDIR)@prefix@/include/coraza/coraza.h

.PHONY: docs swig check-swig-sync check-version-sync
docs:
# build C header doxygen
	@doxygen ./Doxyfile

check-swig-sync:
	@echo "Checking coraza.i is in sync with Go exports..."
	@missing=0; \
	for fn in $$(grep -h '//export ' $(srcdir)/libcoraza/coraza.go | sed 's|.*//export ||'); do \
		if ! grep -qE "(extern|%ignore).*$$fn" $(srcdir)/coraza.i; then \
			echo "  MISSING: $$fn exported from Go but not declared in coraza.i"; \
			missing=1; \
		fi; \
	done; \
	if [ $$missing -eq 0 ]; then \
		echo "  OK: all Go exports are accounted for in coraza.i"; \
	else \
		exit 1; \
	fi

check-version-sync:
	@echo "Checking LIBCORAZA_VERSION_* in libcoraza/coraza.go matches version.txt..."
	@v=`tr -d '[:space:]' < $(srcdir)/version.txt`; \
	fail=0; \
	set -- MAJOR 1 MINOR 2 PATCH 3; \
	while [ $$# -gt 0 ]; do \
		part=`echo $$v | cut -d. -f$$2`; \
		got=`sed -n "s/^#define LIBCORAZA_VERSION_$$1[[:space:]]\{1,\}\([0-9]\{1,\}\).*$$/\1/p" \
			$(srcdir)/libcoraza/coraza.go`; \
		if [ "$$got" != "$$part" ]; then \
			echo "  MISMATCH: LIBCORAZA_VERSION_$$1 is '$$got', version.txt says '$$part'"; \
			fail=1; \
		fi; \
		shift 2; \
	done; \
	if [ $$fail -eq 0 ]; then \
		echo "  OK: version macros match version.txt ($$v)"; \
	else \
		exit 1; \
	fi

check_PROGRAMS = tests/simple_get

if OSX
AM_LDFLAGS = -framework CoreFoundation -framework Security -lresolv
endif

if LINUX
AM_LDFLAGS = -fPIC -pthread -fno-common
endif

tests_simple_get_LDFLAGS = $(AM_LDFLAGS)
tests_simple_get_LDADD = ./libcoraza.a

check: tests/simple_get
	go test -race ./...
	cd tests && ./check_result.sh simple_get

if HAVE_SWIG
# Default target language for SWIG bindings (override with SWIG_LANG=<lang>)
SWIG_LANG ?= python
# Output directory for generated language files (override with SWIG_OUTDIR=<dir>)
SWIG_OUTDIR ?= .

swig: coraza/coraza.h
	@mkdir -p $(SWIG_OUTDIR)
	$(SWIG) -$(SWIG_LANG) -outdir $(SWIG_OUTDIR) -o coraza_wrap.c $(srcdir)/coraza.i
endif
