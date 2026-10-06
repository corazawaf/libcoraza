# Makefile for the libcoraza Lua SWIG example.
# Run from within this directory or from the repository root with:
#   make -C examples/lua

TOPDIR   ?= ../..
SWIG     = swig
CC       = gcc

SWIG_IFACE  = $(TOPDIR)/coraza.i
CORAZA_HDR  = $(TOPDIR)/coraza/coraza.h
LIBCORAZA   = $(TOPDIR)/libcoraza.a

# Detect Lua include flags via pkg-config; fall back to a common system path.
LUA_CFLAGS ?= $(shell pkg-config --cflags lua5.4 2>/dev/null || \
                        pkg-config --cflags lua-5.4 2>/dev/null || \
                        pkg-config --cflags lua 2>/dev/null || \
                        echo "-I/usr/include/lua5.4")
LUA        ?= $(shell command -v lua5.4 2>/dev/null || command -v lua 2>/dev/null || echo lua5.4)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  # On macOS, Lua symbols are resolved at runtime by the interpreter —
  # do not link against liblua.  Go CGO also requires these frameworks.
  EXTRA_LDFLAGS = -undefined dynamic_lookup \
                  -framework CoreFoundation -framework Security -lresolv
  LIBPATH_VAR   = DYLD_LIBRARY_PATH
else
  EXTRA_LDFLAGS =
  LIBPATH_VAR   = LD_LIBRARY_PATH
endif

.PHONY: all run clean

all: coraza.so

# Generate SWIG wrapper: produces coraza_wrap.c in this directory.
coraza_wrap.c: $(SWIG_IFACE) $(CORAZA_HDR)
	$(SWIG) -lua -outdir . -o coraza_wrap.c $(SWIG_IFACE)

# Compile the shared extension module.
coraza.so: coraza_wrap.c $(LIBCORAZA)
	$(CC) -shared -fPIC -o $@ $< \
		-I$(TOPDIR) $(LUA_CFLAGS) \
		-L$(TOPDIR) -lcoraza \
		$(EXTRA_LDFLAGS) \
		-Wno-discarded-qualifiers

run: all
	$(LIBPATH_VAR)=$(TOPDIR):. $(LUA) simple_get.lua

clean:
	rm -f coraza_wrap.c coraza.so
