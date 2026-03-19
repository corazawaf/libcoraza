#!/bin/bash
# Build a vendored orig tarball for Debian packaging.
#
# Launchpad and other Debian build hosts have no network access, so the
# orig tarball must ship everything needed to build offline:
#   - autotools generated files (configure, Makefile.in, ...)
#   - Go vendor/ directory (all Go module dependencies)
#
# The tarball is created from the current git HEAD, not from a GitHub
# release download (which lacks both autotools files and vendor/).
#
# Output: ../libcoraza_<version>.orig.tar.gz
#
# Prerequisites: git, dpkg-parsechangelog, autoconf, automake, libtool, go
#
# Usage: debian/make-orig-tarball.sh
#   Run from the top-level source directory (must be a git repo).

set -euo pipefail

VERSION=$(dpkg-parsechangelog -S Version | sed 's/-.*//')
TARBALL="libcoraza_${VERSION}.orig.tar.gz"
DISTNAME="libcoraza-${VERSION}"
WORKDIR=$(mktemp -d)

trap 'rm -rf "$WORKDIR"' EXIT

echo "==> Exporting git tree..."
git archive --prefix="${DISTNAME}/" HEAD | tar xf - -C "$WORKDIR"

echo "==> Generating autotools files..."
(
    cd "$WORKDIR/${DISTNAME}"
    echo "$VERSION" > .tarball-version
    ./build.sh
)

echo "==> Running go mod vendor..."
(
    cd "$WORKDIR/${DISTNAME}"
    go mod vendor
)

echo "==> Creating tarball..."
tar czf "../${TARBALL}" -C "$WORKDIR" "${DISTNAME}"

echo "==> Created ../${TARBALL}"
echo "    $(tar tzf "../${TARBALL}" | grep -c vendor/) vendor entries included"
