SUBDIRS = ircd ircd/test

distdir = $(PACKAGE).$(VERSION)

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
