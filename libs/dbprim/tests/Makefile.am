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

INCLUDES = -I.. -I$(srcdir)/..

EXTRA_PROGRAMS = test-harness \
		 \
		 t_ll_init t_ll_add t_ll_move t_ll_remove t_ll_find \
		 t_ll_iter t_ll_flush t_le_init \
		 \
		 t_ht_init t_ht_addfind t_ht_move t_ht_remove t_ht_iter \
		 t_ht_flush t_ht_resize t_ht_free t_he_init \
		 \
		 t_st_init

test_harness_SOURCES = test-harness.c
TEST_OPTIONS =

t_ll_init_SOURCES = t_ll_init.c
t_ll_init_LDADD = ../libdbprim.la
t_ll_init_LDFLAGS = -static

t_ll_add_SOURCES = t_ll_add.c
t_ll_add_LDADD = ../libdbprim.la
t_ll_add_LDFLAGS = -static

t_ll_move_SOURCES = t_ll_move.c
t_ll_move_LDADD = ../libdbprim.la
t_ll_move_LDFLAGS = -static

t_ll_remove_SOURCES = t_ll_remove.c
t_ll_remove_LDADD = ../libdbprim.la
t_ll_remove_LDFLAGS = -static

t_ll_find_SOURCES = t_ll_find.c
t_ll_find_LDADD = ../libdbprim.la
t_ll_find_LDFLAGS = -static

t_ll_iter_SOURCES = t_ll_iter.c
t_ll_iter_LDADD = ../libdbprim.la
t_ll_iter_LDFLAGS = -static

t_ll_flush_SOURCES = t_ll_flush.c
t_ll_flush_LDADD = ../libdbprim.la
t_ll_flush_LDFLAGS = -static

t_le_init_SOURCES = t_le_init.c
t_le_init_LDADD = ../libdbprim.la
t_le_init_LDFLAGS = -static

t_ht_init_SOURCES = t_ht_init.c
t_ht_init_LDADD = ../libdbprim.la
t_ht_init_LDFLAGS = -static

t_ht_addfind_SOURCES = t_ht_addfind.c
t_ht_addfind_LDADD = ../libdbprim.la
t_ht_addfind_LDFLAGS = -static

t_ht_move_SOURCES = t_ht_move.c
t_ht_move_LDADD = ../libdbprim.la
t_ht_move_LDFLAGS = -static

t_ht_remove_SOURCES = t_ht_remove.c
t_ht_remove_LDADD = ../libdbprim.la
t_ht_remove_LDFLAGS = -static

t_ht_iter_SOURCES = t_ht_iter.c
t_ht_iter_LDADD = ../libdbprim.la
t_ht_iter_LDFLAGS = -static

t_ht_flush_SOURCES = t_ht_flush.c
t_ht_flush_LDADD = ../libdbprim.la
t_ht_flush_LDFLAGS = -static

t_ht_resize_SOURCES = t_ht_resize.c
t_ht_resize_LDADD = ../libdbprim.la
t_ht_resize_LDFLAGS = -static

t_ht_free_SOURCES = t_ht_free.c
t_ht_free_LDADD = ../libdbprim.la
t_ht_free_LDFLAGS = -static

t_he_init_SOURCES = t_he_init.c
t_he_init_LDADD = ../libdbprim.la
t_he_init_LDFLAGS = -static

t_st_init_SOURCES = t_st_init.c
t_st_init_LDADD = ../libdbprim.la
t_st_init_LDFLAGS = -static

EXTRA_DIST = test-harness.dat

check: $(EXTRA_PROGRAMS)
	./test-harness -I. -I$(srcdir) $(TEST_OPTIONS)
