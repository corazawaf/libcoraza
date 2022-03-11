
noinst_PROGRAMS = simple_get
simple_get_SOURCES = simple_get.c

if OSX
AM_LDFLAGS = -framework CoreFoundation
endif

simple_get_LDFLAGS = $(AM_LDFLAGS) -I../ -L../ -R$(PWD)/../

simple_get_LDADD = -lcorazacore

test: simple_get
	./simple_get

.PHONY = test
