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
# $Id: convert-conf.py,v 1.2 2005-02-19 21:50:48 isomer Exp $
#

import sys
from string import *
import re

if len(sys.argv) > 1:
	f = open(sys.argv[1], "r")
else:
	f = sys.stdin

connects = {}
jupes = []
feats = [ ("OPLEVELS","FALSE")]

def qstr(s):
	return replace(s,'"','\\"')

def istr(s):
	return str(int(strip(s)))
	

def do_uline(parts):
	print "Uworld {"
	print "\tname = \"%s\";" % qstr(parts[1])
	print "};"
	print
	if len(parts[2]):
		for i in split(parts[2],","):
			jupes.append(i)

def do_hline(parts):
	if not connects.has_key(lower(parts[3])):
		connects[lower(parts[3])]={
			"name" : lower(parts[3])
		}
	connects[lower(parts[3])]["hub"] = parts[1]

def do_lline(parts):
	if not connects.has_key(lower(parts[3])):
		connects[lower(parts[3])]={
			"name" : lower(parts[3])
		}
	del connects[lower(parts[3])]["hub"]

def do_pline(parts):
	print "Port {"
	print "\tport = %s;" % istr(parts[4])
	if len(parts[1]):
		print "\tmask = \"%s\";" % qstr(parts[1])
	if len(parts[2]):
		print "\tvhost = \"%s\";" % qstr(parts[2])
	if count(parts[3], 'S'):
		print "\tserver = yes;"
	if count(parts[3], 'H'):
		print "\thidden = yes;"
	print "};"
	print

def do_fline(parts):
	feats.append((parts[1], parts[2]))

def do_kline(parts):
	if len(parts)!=4:
		sys.stderr.write("WARNING: Wrong number of parameters on line %i\n" % lno)
		return
	letter,host,reason,user=parts
	print "Kill {"
	if host[:2]=="$R":
		if host=="$R":
			sys.stderr.write("WARNING: Empty realname kline on line %i\n" % lno)
		print "\trealname = \"%s\";" % qstr(host[2:])
	else:
		print "\thost = \"%s@%s\";" % (qstr(user),qstr(host))
	if reason[:1]=="!":
		print "\tfile = \"%s\";" % qstr(reason[1:])
	else:
		print "\treason = \"%s\";" % qstr(reason)
	print "};"
	print

def do_iline(parts):
	if len(parts)!=6:
		sys.stderr.write("WARNING: I:line doesn't have enough fields on line %i\n" % lno)
		return
	iline,ip,password,host,dummy,clss = parts
	for i in [0,1]:
		mask = [ip,host][i]
		# Ignore things that aren't masks
		if "." not in mask and "*" not in mask and "@" not in mask:
			continue
		if "@" in mask:
			user,host = split(mask,"@")
		else:
			user,host = "*",mask
		if i==0 and not re.match("^[0-9\.\*]+$",host):
			sys.stderr.write("WARNING: Bad IP mask in line %s (%s)\n" % (lno,repr(mask)))
			continue
		print "Client {"
		if re.match("^[1-9][1-9]?$",password):
			print "\tmaxlinks = %s;" % int(password)
		elif password:
			print "\tpassword = \"%s\";" % qstr(password)
		print "\tclass = \"%s\";" % clss
		if i == 0:
			print "\tip = \"%s\";" % qstr(host)
		else:
			print "\thost = \"%s\";" % qstr(host)
		if user!="*":
			print "\tusername = \"%s\";" % qstr(user)
		print "};"
		print

def do_cline(parts):
	name=lower(parts[3])
	if not connects.has_key(name):
		connects[name]={}
	connects[name]["host"]=parts[1]
	connects[name]["password"]=parts[2]
	connects[name]["name"]=parts[3]
	connects[name]["port"]=parts[4]
	connects[name]["class"]=parts[5]

cvtmap = {
	'M': ('General', ('name', 'vhost', 'description', '', '!numeric'), ''),
	'A': ('Admin', ('location', 'contact', 'contact'), ''),
	'Y': ('Class', ('name', '!pingfreq', '!connectfreq', '!maxlinks', '!sendq'), ''),
	'I': do_iline,
	'T': ('motd', ('host', 'file'), ''),
	'U': do_uline,
	'H': do_hline,
	'L': do_lline,
	'K': do_kline,
	'k': do_kline,
	'C': do_cline,
	'D': ('CRULE', ('server', '', 'rule'), '\tall = yes;'),
	'd': ('CRULE', ('server', '', 'rule'), ''),
	'O': ('Operator', ('host', 'password', 'name', '', 'class'), '\tlocal = no;'),
	'o': ('Operator', ('host', 'password', 'name', '', 'class'), '\tlocal = yes;'),
	'P': do_pline,
	'F': do_fline
}

lno=0
for line in f.readlines():
	lno=lno+1
	line = strip(line)
	if line=="":
		continue
	if line[0]=="#":
		print "#"+line
		continue
	print "#",line
	parts = split(line, ":")
	parts=['']
	# This statemachine is pretty much directly stolen from ircu
	# to give an "authentic" parser :)
	state=0 # normal
	quoted=0
	for i in line:
		if state==0:
			if i=="\\":
				state=1 # escaped
			elif i=='"':
				quoted=not quoted
			elif i==':':
				if quoted:
					parts[-1]=parts[-1]+i
				else:
					parts.append("")
			elif i=='#':
				break
			else:
				parts[-1]=parts[-1]+i
		elif state==1:
			if i in "bfnrtv":
				parts[-1]=parts[-1]+"\b\f\n\r\t\v"[index("bfnrtv",i)]
			else:
				parts[-1]=parts[-1]+i
			state=0
	if quoted:
		sys.stderr.write("WARNING: No closing quote on line %i\n"%lno)
	if not len(parts):
		continue
	if not cvtmap.has_key(parts[0]):
		print "#Unknown:",line
		continue
	if callable(cvtmap[parts[0]]):
		cvtmap[parts[0]](parts)
		continue
	(block, items, extra) = cvtmap[parts[0]]

	print block, "{"
	idx = 1
	for item in items:
		if idx >= len(parts):
			break
		if len(parts[idx]) and len(item):
			if item[0] == '!':
				print "\t%s = %s;" % (item[1:], istr(parts[idx]))
			else:
				print "\t%s = \"%s\";" % (item, qstr(parts[idx]))
		idx = idx + 1
	if len(extra):
		print extra
	print "};"
	print

if len(jupes):
	print "Jupe {"
	for nick in jupes:
		print "\tnick = \"%s\";" % qstr(nick)
	print "};"
	print

if len(connects.keys()):
	for i in connects.keys():
		print "Connect {"
		print "\tname = \"%s\";" % qstr(connects[i]["name"])
		print "\thost = \"%s\";" % qstr(connects[i]["host"])
		print "\tpassword = \"%s\";" % qstr(connects[i]["password"])
		print "\tport = %s;" % connects[i]["port"]
		print "\tclass = \"%s\";" % qstr(connects[i]["class"])
		if connects[i].has_key("hub"):
			print "\thub = \"%s\";" % qstr(connects[i]["hub"])
		else:
			print "\tleaf = \"yes\";"
		print "};"
		print

if len(feats):
	print "features {"
	for (name, value) in feats:
		print "\t\"%s\" = \"%s\";" % (qstr(name), qstr(value))
	print "};"
	print
