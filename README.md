# C library for OWASP Coraza Web Application Firewall v2

Welcome to libcoraza, the C library for OWASP Coraza Web Application Firewall. Because [Coraza](https://github.com/corazawaf/coraza) was made in golang, if you want to embed in any kind of C application, you will need this library.

## Prerequisites

* a C compiler:
  * gcc or
  * clang
* Golang compiler v1.18+
* libtools
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

## Run test

If you want to try the given example, try:

```
cd tests
make
./simple_get
```

## Build offline or different branch/commit

If you want to compile the library from different branch/commit than
master or HEAD, or want to make package offline, get the code and use
it as vendor:

```
go get -u github.com/corazawaf/coraza/v2@HASH-ID
go mod vendor
go mod tidy
./build.sh
./configure
make
```

If you didn't installed the builded library (skipped the `sudo make install` step), you should set the LD_LIBRARY_PATH:

```
export LD_LIBRARY_PATH=../:$LID_LIBRARY_PATH
```
