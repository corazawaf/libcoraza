# C library for OWASP Coraza Web Application Firewall v2

Welcome to libcoraza, the C library for OWASP Coraza Web Application Firewall. Because [Coraza](https://github.com/corazawaf/coraza) has made in golang, if you want to embed in any kind of C application, you will need this library.

## Prerequisites

* a C compiler:
  * gcc or
  * clang
* Golang compiler v1.16+
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

If you didn't installed the builded library (skipped the `sudo make install` step), you should set the LD_LIBRARY_PATH:

```
export LD_LIBRARY_PATH=../:$LID_LIBRARY_PATH
```
