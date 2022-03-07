
if LINUX
all: build-linux
test: test-linux
endif
if OSX
all: build-osx
test: test-osx
endif

build-linux:
	@CC@ -I../ -L../ simple_get.c -o simple_get -lcorazacore
test-linux: build-linux
	LD_LIBRARY_PATH=../ ./simple_get

build-osx:
	@CC@ -I../ ../libcorazacore.dylib simple_get.c -o simple_get
test-osx: build-osx
	LD_LIBRARY_PATH=../ ./simple_get

clean-local:
	rm -f simple_get
