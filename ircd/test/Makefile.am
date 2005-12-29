## AutoMake Makefile for the Undernet IRC Daemon sources
##
## Copyright (C) 2005 by Michael Poole <mdpoole@troilus.org>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
##
## @(#)$Id$

AM_CPPFLAGS = -I${top_srcdir}/include -I.. -I../..

check_PROGRAMS = \
	ircd_chattr_t \
	ircd_in_addr_t \
	ircd_match_t \
	ircd_string_t

ircd_chattr_t_SOURCES = \
	ircd_chattr_t.c \
	test_stub.c \
	../ircd_string.c

ircd_in_addr_t_SOURCES = \
	ircd_in_addr_t.c \
	test_stub.c \
	../ircd_alloc.c \
	../ircd_string.c \
	../match.c \
	../numnicks.c

ircd_match_t_SOURCES = \
	ircd_match_t.c \
	test_stub.c \
	../ircd_string.c \
	../match.c

ircd_string_t_SOURCES = \
	ircd_string_t.c \
	test_stub.c \
	../ircd_string.c
