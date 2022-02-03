all: library-osx

library-osx:
	CC=clang go build -buildmode=c-shared -o coraza_core.dylib core/core.go
	CC=clang go build -buildmode=c-shared -o coraza_utils.dylib utils/utils.go

library-linux:
	CC=clang go build -buildmode=c-shared -o coraza_core.so core/core.go
	CC=clang go build -buildmode=c-shared -o coraza_utils.so utils/utils.go

clean:
	rm -f *.o *.so *.slo *.lo *.la *.h *.dylib