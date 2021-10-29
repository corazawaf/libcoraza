all: library module

module:
	apxs -i -Wc,-fPIC -Wc,-O0 -a -c mod_coraza.c coraza_config.c coraza_filters.c coraza_utils.c coraza.dylib

library:
	CC=clang go build -buildmode=c-shared -o coraza.dylib export.go

install:
	apxs -i -n mod_coraza .libs/mod_coraza.so

clean:
	rm -f core *.o *.so *.slo *.lo *.la coraza.h