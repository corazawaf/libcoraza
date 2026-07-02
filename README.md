# C library for OWASP Coraza Web Application Firewall

Welcome to libcoraza, the C library for OWASP Coraza Web Application Firewall. Because [Coraza](https://github.com/corazawaf/coraza) was made in Go, if you want to embed it in any kind of C application, you will need this library.

## Prerequisites

* A C compiler:
  * gcc or
  * clang
* Go compiler v1.25+
* libtool
* autotools
* make

## Download

Download the library source:

```
git clone https://github.com/corazawaf/libcoraza libcoraza
```

## Install from PPA (Ubuntu)

Prebuilt packages are available from a Launchpad PPA:
https://launchpad.net/~pierrepomes/+archive/ubuntu/libcoraza

```shell
# add-apt-repository lives in software-properties-common on minimal images
sudo apt install software-properties-common
sudo add-apt-repository ppa:pierrepomes/libcoraza
sudo apt update
sudo apt install libcoraza1      # runtime library
sudo apt install libcoraza-dev   # headers, for building connectors
```

Built for Ubuntu 22.04 (jammy), 24.04 (noble), 26.04 (resolute) and 26.10 (stonking).

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

If you didn't install the built library (skipped the `sudo make install` step), set the library path before running your application:

```
# Linux
export LD_LIBRARY_PATH=../:$LD_LIBRARY_PATH

# macOS
export DYLD_LIBRARY_PATH=../:$DYLD_LIBRARY_PATH
```

## SWIG language bindings

libcoraza ships a [SWIG](https://www.swig.org) interface file (`coraza.i`) that allows
generating bindings for a wide range of languages including Python, Ruby, Java, PHP,
Perl, and many others.

### Prerequisites

* SWIG 4.0 or later

Install on Debian/Ubuntu:

```
sudo apt install swig
```

Install on macOS (Homebrew):

```
brew install swig
```

### Ready-made examples

The `examples/` directory contains fully working examples with their own Makefiles:

```
# Python
make -C examples/python      # build
make -C examples/python run  # build and run

# Java (requires JAVA_HOME to be set)
make -C examples/java        # build
make -C examples/java run    # build and run
```

Each example exercises the full API including error and debug log callbacks.

### Building bindings for other languages

First build the library:

```
./build.sh
./configure
make
```

Then invoke SWIG directly against `coraza.i`:

```
# Ruby example
swig -ruby -o coraza_wrap.c coraza.i
gcc -shared -fPIC coraza_wrap.c $(ruby -rrbconfig -e 'puts RbConfig::CONFIG["CFLAGS"]') \
    -L. -lcoraza -o coraza.so
```

### Notes

* **Callbacks** — `coraza_set_error_callback` and `coraza_set_debug_log_callback` are
  provided as language-specific trampolines for Python and Java (see `coraza.i` and the
  example directories). For other languages, refer to the SWIG documentation on
  `%callback` or director classes.
* `coraza_matched_rule_get_error_log` returns a string owned by the caller.
  The generated wrapper takes ownership automatically so the target language
  runtime frees it when the object is garbage collected.
