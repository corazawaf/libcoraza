# Makefile for the libcoraza Python SWIG example.
# Run from within this directory or from the repository root with:
#   make -C examples/python

TOPDIR   ?= ../..
SWIG     = swig
CC       = gcc
PYTHON   = python3

SWIG_IFACE  = $(TOPDIR)/coraza.i
CORAZA_HDR  = $(TOPDIR)/coraza/coraza.h
LIBCORAZA   = $(TOPDIR)/libcoraza.a

PY_INCLUDES := $(shell $(PYTHON)-config --includes)

.PHONY: all run clean

all: _coraza.so

# Generate SWIG wrapper: produces coraza.py + _coraza_wrap.c in this directory.
coraza.py _coraza_wrap.c: $(SWIG_IFACE) $(CORAZA_HDR)
	$(SWIG) -python -outdir . -o _coraza_wrap.c $(SWIG_IFACE)

# Compile the shared extension module.
_coraza.so: _coraza_wrap.c $(LIBCORAZA)
	$(CC) -shared -fPIC -o $@ $< \
		-I$(TOPDIR) $(PY_INCLUDES) \
		-L$(TOPDIR) -lcoraza \
		-Wno-discarded-qualifiers

run: all
	LD_LIBRARY_PATH=$(TOPDIR) $(PYTHON) simple_get.py

clean:
	rm -f coraza.py _coraza_wrap.c _coraza.so
	rm -rf __pycache__
