all: library-osx

library-osx:
	CC=clang go build -buildmode=c-shared -o coraza_core.dylib core/core.go
	CC=clang go build -buildmode=c-shared -o coraza_utils.dylib utils/utils.go
	CC=clang go build -buildmode=c-archive -o coraza_core.a core/core.go
	CC=clang go build -buildmode=c-archive -o coraza_utils.a utils/utils.go

library-linux:
	CC=clang go build -buildmode=c-shared -o coraza_core.so core/core.go
	CC=clang go build -buildmode=c-shared -o coraza_utils.so utils/utils.go

clean:
	rm -f *.o *.so *.slo *.lo *.la *.h *.dylib docs/* tests/*.o

test: library-osx
	cd tests && make test
.PHONY: docs
docs: 
# build C header doxygen
	@doxygen ./Doxyfile