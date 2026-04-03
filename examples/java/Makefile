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
  JAVA_INC_OS   = $(JAVA_HOME)/include/darwin
  JNI_LIB       = libcoraza_jni.dylib
  # -force_load ensures all symbols from the static archive are included so
  # libcoraza_jni.dylib is self-contained (no runtime libcoraza.dylib needed).
  JNI_LDFLAGS   = -dynamiclib -Wl,-force_load,$(LIBCORAZA) \
                  -framework CoreFoundation -framework Security -lresolv
  LIBPATH_VAR   = DYLD_LIBRARY_PATH
else
  JAVA_INC_OS   = $(JAVA_HOME)/include/linux
  JNI_LIB       = libcoraza_jni.so
  # --whole-archive embeds the static library so the .so is self-contained.
  JNI_LDFLAGS   = -shared -Wl,--whole-archive $(LIBCORAZA) -Wl,--no-whole-archive
  LIBPATH_VAR   = LD_LIBRARY_PATH
endif

.PHONY: all run clean

all: $(JNI_LIB) gen/SimpleGet.class

# Create the output directory for generated Java sources.
gen/:
	mkdir -p gen

# Generate SWIG wrapper: produces Java sources in gen/ and coraza_wrap.c here.
gen/coraza.java coraza_wrap.c: $(SWIG_IFACE) $(CORAZA_HDR) | gen/
	$(SWIG) -java -outdir gen/ -o coraza_wrap.c $(SWIG_IFACE)

# Compile the JNI shared library.
# The static archive is embedded via JNI_LDFLAGS (force_load / whole-archive)
# so no separate -lcoraza is needed at link time.
$(JNI_LIB): coraza_wrap.c $(LIBCORAZA)
	$(CC) $(JNI_LDFLAGS) -fPIC -o $@ $< \
		-I$(TOPDIR) -I$(JAVA_INC) -I$(JAVA_INC_OS) \
		-Wno-discarded-qualifiers

# Compile the Java example (depends on the generated Java sources and callback interfaces).
gen/SimpleGet.class: gen/coraza.java $(JNI_LIB) SimpleGet.java \
                     CorazaErrorCallback.java CorazaDebugLogCallback.java
	$(JAVAC) -d gen/ gen/*.java SimpleGet.java \
	    CorazaErrorCallback.java CorazaDebugLogCallback.java

run: all
	$(LIBPATH_VAR)=$(TOPDIR):. $(JAVA) \
		-cp gen/ \
		-Djava.library.path=. \
		SimpleGet

clean:
	rm -rf gen/ libcoraza_jni.so libcoraza_jni.dylib coraza_wrap.c
