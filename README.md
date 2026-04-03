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

### Building bindings

First build the library and generate the C header:

```
./build.sh
./configure
make
```

Then run the `swig` Makefile target, optionally specifying the target language
via `SWIG_LANG` (default: `python`):

```
# Python bindings (default)
make swig

# Ruby bindings
make swig SWIG_LANG=ruby

# Java bindings
make swig SWIG_LANG=java
```

This generates `coraza_wrap.c` (and a language-specific source file such as
`coraza.py`) that can be compiled together with the `libcoraza` shared library
into a loadable extension module.

### Python example

```
make swig SWIG_LANG=python
gcc -shared -fPIC coraza_wrap.c $(python3-config --includes) \
    -L. -lcoraza -o _coraza.so
python3 -c "import coraza; waf = coraza.coraza_new_waf_config(); print(waf)"
```

### Notes

* The callback-based functions (`coraza_add_debug_log_callback` and
  `coraza_add_error_callback`) are excluded from the default SWIG wrapper
  because function pointer handling is language-specific. Refer to the SWIG
  documentation on `%callback` or director classes to re-enable them for
  your target language.
* `coraza_matched_rule_get_error_log` returns a string owned by the caller.
  The generated wrapper takes ownership automatically so the target language
  runtime frees it when the object is garbage collected.
