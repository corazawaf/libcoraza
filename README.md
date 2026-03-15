# C library for OWASP Coraza Web Application Firewall

Welcome to libcoraza, the C library for OWASP Coraza Web Application Firewall. Because [Coraza](https://github.com/corazawaf/coraza) was made in Go, if you want to embed it in any kind of C application, you will need this library.

## Prerequisites

* A C compiler:
  * gcc or
  * clang
* Go compiler v1.24+
* libtool
* autotools
* make

## Download

Download the library source:

```
git clone https://github.com/corazawaf/libcoraza libcoraza
```

## Build

Build the source:

```
cd libcoraza
./build.sh
./configure
make
sudo make install
```

## Run tests

Run the full test suite (Go tests with race detection + C test validation):

```
make check
```

## Build offline or different branch/commit

If you want to compile the library from a different branch/commit than
main or HEAD, or want to make a package offline, get the code and use
it as vendor:

```
go get -u github.com/corazawaf/coraza/v3@HASH-ID
go mod vendor
go mod tidy
./build.sh
./configure
make
```

If you didn't install the built library (skipped the `sudo make install` step), you should set the LD_LIBRARY_PATH:

```
export LD_LIBRARY_PATH=../:$LD_LIBRARY_PATH
```
