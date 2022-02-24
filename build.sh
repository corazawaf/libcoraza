#!/bin/sh

# remove old files
rm -rf autom4te.cache
rm -f aclocal.m4

case `uname` in
    Darwin*) glibtoolize --force --copy
    ;;
    *) libtoolize --force --copy
    ;;
esac

autoreconf --install
autoheader
automake --foreign --copy
autoconf --force

rm -rf autom4te.cache

