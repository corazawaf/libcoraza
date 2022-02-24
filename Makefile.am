
ACLOCAL_AMFLAGS = -I macros

CLEANFILES = *.o *.so *.slo *.lo *.la *.h *.dylib

if LINUX
all: build-linux
install: install-linux
test: test-linux
endif
if OSX
all: build-osx
install: install-osx
test: test-osx
endif

build-linux:
	CC=@CC@ go build -buildmode=c-archive -o libcorazacore.a libcoraza-core/core.go
	CC=@CC@ go build -buildmode=c-archive -o libcorazautils.a libcoraza-utils/utils.go
	CC=@CC@ go build -buildmode=c-shared -o libcorazacore.so libcoraza-core/core.go
	CC=@CC@ go build -buildmode=c-shared -o libcorazautils.so libcoraza-utils/utils.go
	mv libcorazacore.h coraza_core.h
	mv libcorazautils.h coraza_utils.h

build-osx:
	CC=@CC@ go build -buildmode=c-archive -o coraza_core.dylib libcoraza-core/core.go
	CC=@CC@ go build -buildmode=c-archive -o coraza_utils.dylib libcoraza-utils/utils.go
	mv libcorazacore.h coraza_core.h
	mv libcorazautils.h coraza_utils.h

install-linux:
	test -d @prefix@ || mkdir -p @prefix@
	test -d @prefix@/lib || mkdir -p @prefix@/lib
	test -d @prefix@/include || mkdir -p @prefix@/include
	@INSTALL@ libcorazacore.a @prefix@/lib/
	@INSTALL@ libcorazautils.a @prefix@/lib/
	@INSTALL@ libcorazacore.so @prefix@/lib/
	@INSTALL@ libcorazautils.so @prefix@/lib/
	@INSTALL@ coraza_core.h @prefix@/include/
	@INSTALL@ coraza_utils.h @prefix@/include/

install-osx:
	mkdir -p /usr/local/coraza/lib
	mkdir -p /usr/local/coraza/include
	mv coraza_core.dylib coraza_core.a /usr/local/coraza/lib/
	mv coraza_core.h /usr/local/coraza/include/

test-linux: build-linux
	cd tests && make test

test-osx: build-osx
	cd tests && make test

.PHONY: docs
docs:
# build C header doxygen
	@doxygen ./Doxyfile

clean-local:
	cd tests && make clean

