AC_PREREQ([2.60])

AC_INIT([libcoraza],
        m4_esyscmd([build-aux/git-version-gen .tarball-version]),
        [https://github.com/corazawaf/libcoraza/issues],
        [libcoraza],
        [https://github.com/corazawaf/libcoraza])

# General automake options.
AC_CONFIG_MACRO_DIRS([macros build-aux])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall -Werror])

dnl Disable verbose mode
dnl To enable, use --disable-silent-rules
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# General definitions
AC_PREFIX_DEFAULT([/usr/local])

# Check for dependencies: C, AR, Make
AC_PROG_CC
AC_PROG_CPP
AM_PROG_AR
AC_PROG_MAKE_SET
AC_CHECK_PROG([GOCOMPILER], [go], "true", "false")
if test -z "$GOCOMPILER"; then
  AC_MSG_ERROR("Go does not found")
else
  AC_SUBST([GOVERSION], [$(go version | cut -d" " -f3)])
fi
PKG_PROG_PKG_CONFIG

# check host os
AC_CANONICAL_HOST

build_linux=no
build_mac=no
os_type=unknown

# Detect the target system
case "${host_os}" in
    linux*)
        build_linux=yes
        os_type=Linux
        ;;
    darwin*)
        build_mac=yes
        os_type=Darwin
        ;;
    *)
        AC_MSG_ERROR(["OS $host_os is not supported"])
        ;;
esac

# Pass the conditionals to automake
AM_CONDITIONAL([LINUX], [test "$build_linux" = "yes"])
AM_CONDITIONAL([OSX], [test "$build_mac" = "yes"])

LT_INIT

# There is only one Makefile
AC_CONFIG_FILES([
                 Makefile
                 Doxyfile
                 ])

AC_OUTPUT

echo \
"----------------------------------------------------------------------

 ${PACKAGE_NAME} Version ${PACKAGE_VERSION} configuration:

 OS Type	${os_type}
 Prefix 	${prefix}
 Preprocessor	${CPP} ${CPPFLAGS}
 C Compiler	${CC} ${CFLAGS}
 Go Version	${GOVERSION}

-----------------------------------------------------------------------"
