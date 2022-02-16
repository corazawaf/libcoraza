all: library-osx

library-osx:
	clang -I../ ../coraza_core.dylib simple_get.c -o simple_get.o
test: library-osx
	DYLD_LIBRARY_PATH=../ ./simple_get.o

clean:
	rm -f *.o *.so *.slo *.lo *.la *.h *.dylib