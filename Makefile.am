SUBDIRS = ircd ircd/test

distdir = $(PACKAGE).$(VERSION)

MAINTAINERCLEANFILES = \
    configure \
    aclocal.m4 \
    config.h.in \
    config.h.in~ \
    config.guess \
    config.sub \
    configure~ \
    install-sh \
    missing \
    depcomp \
    compile \
    ylwrap \
    Makefile.in \
    ircd/Makefile.in \
    ircd/test/Makefile.in

EXTRA_DIST = \
    acinclude.m4 \
    doc \
    include \
    patches \
    tests \
    tools \
    ircd-patch \
    INSTALL \
    INSTALL_FR \
    LICENSE \
    RELEASE.NOTES \
    ChangeLog.11 \
    ChangeLog.12 \
    Doxyfile

dist-hook:
	rm -rf `find $(distdir) -name __pycache__ -o -name .pytest_cache`
