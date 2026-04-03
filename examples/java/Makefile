# Makefile for the libcoraza Java SWIG example.
# Run from within this directory or from the repository root with:
#   make -C examples/java

TOPDIR   ?= ../..
SWIG     = swig
CC       = gcc
JAVAC    = javac
JAVA     = java

SWIG_IFACE  = $(TOPDIR)/coraza.i
CORAZA_HDR  = $(TOPDIR)/coraza/coraza.h
LIBCORAZA   = $(TOPDIR)/libcoraza.a

ifndef JAVA_HOME
  $(error JAVA_HOME is not set. Install a JDK and set JAVA_HOME before running make.)
endif

JAVA_INC    = $(JAVA_HOME)/include
UNAME_S    := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  JAVA_INC_OS = $(JAVA_HOME)/include/darwin
else
  JAVA_INC_OS = $(JAVA_HOME)/include/linux
endif

.PHONY: all run clean

all: libcoraza_jni.so gen/SimpleGet.class

# Create the output directory for generated Java sources.
gen/:
	mkdir -p gen

# Generate SWIG wrapper: produces Java sources in gen/ and coraza_wrap.c here.
gen/coraza.java coraza_wrap.c: $(SWIG_IFACE) $(CORAZA_HDR) | gen/
	$(SWIG) -java -outdir gen/ -o coraza_wrap.c $(SWIG_IFACE)

# Compile the JNI shared library.
libcoraza_jni.so: coraza_wrap.c $(LIBCORAZA)
	$(CC) -shared -fPIC -o $@ $< \
		-I$(TOPDIR) -I$(JAVA_INC) -I$(JAVA_INC_OS) \
		-L$(TOPDIR) -lcoraza \
		-Wno-discarded-qualifiers

# Compile the Java example (depends on the generated Java sources and callback interfaces).
gen/SimpleGet.class: gen/coraza.java libcoraza_jni.so SimpleGet.java \
                     CorazaErrorCallback.java CorazaDebugLogCallback.java
	$(JAVAC) -d gen/ gen/*.java SimpleGet.java \
	    CorazaErrorCallback.java CorazaDebugLogCallback.java

run: all
	LD_LIBRARY_PATH=$(TOPDIR):. $(JAVA) \
		-cp gen/ \
		-Djava.library.path=. \
		SimpleGet

clean:
	rm -rf gen/ libcoraza_jni.so coraza_wrap.c
