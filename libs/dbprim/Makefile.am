## Prefered emacs editing mode: -*- Makefile -*-
##
## Copyright (C) 2002 by Kevin L. Mitchell <klmitch@mit.edu>
##
## This library is free software; you can redistribute it and/or
## modify it under the terms of the GNU Library General Public
## License as published by the Free Software Foundation; either
## version 2 of the License, or (at your option) any later version.
##
## This library is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## Library General Public License for more details.
##
## You should have received a copy of the GNU Library General Public
## License along with this library; if not, write to the Free
## Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
## MA 02111-1307, USA
##
## @(#)$Id$
##
## Process this file with automake to generate Makefile.in

AUTOMAKE_OPTIONS = foreign

# The . here forces prefix ordering, so make check rebuilds the
# library first if necessary
SUBDIRS = . tests

lib_LTLIBRARIES = libdbprim.la
libdbprim_la_SOURCES = dbprim_int.h \
		       \
		       _hash_prime.c he_init.c ht_add.c ht_find.c ht_flush.c \
		       ht_free.c ht_init.c ht_iter.c ht_move.c ht_remove.c \
		       ht_resize.c \
		       \
		       le_init.c ll_add.c ll_find.c ll_flush.c ll_init.c \
		       ll_iter.c ll_move.c ll_remove.c \
		       \
		       sh_find.c sh_flush.c sh_init.c sh_iter.c sh_move.c \
		       _smat_comp.c smat_freelist.c _smat_hash.c \
		       _smat_resize.c st_add.c st_find.c st_flush.c st_free.c \
		       st_init.c st_iter.c st_remove.c st_resize.c
libdbprim_la_LIBADD = @DBPRIM_ET_OBJS@
libdbprim_la_DEPENDENCIES = @DBPRIM_ET_OBJS@
libdbprim_la_LDFLAGS = -version-info 1:1:0

include_HEADERS = dbprim.h

EXTRA_DIST = dbprim.h.top dbprim.h.bot dbprim_err.et \
	     comp_et-sh.in COPYING INSTALL doc

SUFFIXES = .et .h

CLEANFILES = dbprim.h dbprim_err.c dbprim_err.h

.et.c .et.h: comp_et-sh
	$(SHELL) comp_et-sh --com_err=@COM_ERR@ --dir=$(top_builddir) $<

dbprim_err.c dbprim_err.h: dbprim_err.et

$(OBJECTS): dbprim.h

dbprim.h: $(srcdir)/dbprim.h.top dbprim_err.h $(srcdir)/dbprim.h.bot
	cat $(srcdir)/dbprim.h.top dbprim_err.h \
		$(srcdir)/dbprim.h.bot > dbprim.h

dist-hook:
	rm -f dbprim.h dbprim_err.c dbprim_err.h
