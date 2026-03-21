#!/bin/sh
# Generate configure and Makefile.in files from autoconf/automake sources.
# Run this after a fresh checkout or after modifying configure.ac/Makefile.am.

set -e
autoreconf -ivf
