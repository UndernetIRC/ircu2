#!/usr/bin/env python
#
# IRC - Internet Relay Chat, tools/convert-conf.py
# Copyright (C) 2002 Alex Badea <vampire@p16.pub.ro>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 1, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#
# Configuration file converter from 2.10.11 to 2.10.12 format
# Usage:
#   convert-conf.py < old.conf > new.conf
#
# $Id: convert-conf.py,v 1.1 2002-04-09 22:40:56 vampire Exp $
#

import sys
from string import *

if len(sys.argv) > 1:
	f = open(sys.argv[1], "r")
else:
	f = sys.stdin

servers = {}
jupes = []
feats = []

def do_uline(parts):
	if not servers.has_key(parts[1]):
		servers[parts[1]] = ['*', 0, 0, 0]
	servers[parts[1]][1] = 1
	if len(parts[2]):
		jupes.append(parts[2])

def do_hline(parts):
	if not servers.has_key(parts[3]):
		servers[parts[3]] = ['*', 0, 0, 0]
	servers[parts[3]][0] = parts[1]
	servers[parts[3]][2] = 1

def do_lline(parts):
	if not servers.has_key(parts[3]):
		servers[parts[3]] = ['*', 0, 0, 0]
	servers[parts[3]][0] = parts[1]
	servers[parts[3]][3] = 1

def do_pline(parts):
	print "#", join(parts, ":")
	print "Port {"
	print "\tport = %s;" % parts[4]
	if len(parts[1]):
		print "\tmask = \"%s\";" % parts[1]
	if len(parts[2]):
		print "\tvhost = \"%s\";" % parts[2]
	if count(parts[3], 'S'):
		print "\tserver = yes;"
	if count(parts[3], 'H'):
		print "\thidden = yes;"
	print "};"
	print

def do_fline(parts):
	feats.append((parts[1], parts[2]))

cvtmap = {
	'M': ('General', ('name', 'vhost', 'description', '', '!numeric'), ''),
	'A': ('Admin', ('location', 'contact', 'contact'), ''),
	'Y': ('Class', ('name', '!pingfreq', '!connectfreq', '!maxlinks', '!sendq'), ''),
	'I': ('Client', ('ip', 'password', 'host', '', 'class'), ''),
	'T': ('motd', ('host', 'file'), ''),
	'U': do_uline,
	'H': do_hline,
	'L': do_lline,
	'K': ('Kill', ('host', 'reason'), ''),
	'k': ('Kill', ('host', 'reason'), ''),
	'C': ('Connect', ('host', 'password', 'name', '!port', 'class'), ''),
	'D': ('CRULE', ('server', '', 'rule'), '\tall = yes;'),
	'd': ('CRULE', ('server', '', 'rule'), ''),
	'O': ('Operator', ('host', 'password', 'name', '', 'class'), '\tlocal = no;'),
	'o': ('Operator', ('host', 'password', 'name', '', 'class'), '\tlocal = yes;'),
	'P': do_pline,
	'F': do_fline
}

for line in f.readlines():
	line = strip(line)
	parts = split(line, ":")
	if not len(parts):
		continue
	if not cvtmap.has_key(parts[0]):
		continue
	if callable(cvtmap[parts[0]]):
		cvtmap[parts[0]](parts)
		continue
	(block, items, extra) = cvtmap[parts[0]]
	print "#", line
	print block, "{"
	idx = 1
	for item in items:
		if idx >= len(parts):
			break
		if len(parts[idx]) and len(item):
			if item[0] == '!':
				print "\t%s = %s;" % (item[1:], parts[idx])
			else:
				print "\t%s = \"%s\";" % (item, parts[idx])
		idx = idx + 1
	if len(extra):
		print extra
	print "};"
	print

for server in servers.keys():
	(mask, uw, hub, leaf) = servers[server]
	print "Server {"
	print "\tname = \"%s\";" % server
	print "\tmask = \"%s\";" % mask
	if uw: print "\tuworld = yes;"
	if hub: print "\thub = yes;"
	if leaf: print "\tleaf = yes;"
	print "};"
	print

if len(jupes):
	print "Jupe {"
	for nick in jupes:
		print "\tnick = \"%s\";" % nick
	print "};"
	print

if len(feats):
	print "features {"
	for (name, value) in feats:
		print "\t\"%s\" = \"%s\";" % (name, value)
	print "};"
	print
