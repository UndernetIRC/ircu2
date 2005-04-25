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
# $Id: convert-conf.py,v 1.8 2005-04-25 04:04:17 isomer Exp $
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
opers = []
quarintines = []

useable_features = [
	"LOG", "DOMAINNAME", "RELIABLE_CLOCK", "BUFFERPOOL", 
	"HAS_FERGUNSON_FLUSHER", "CLIENT_FLOOD", "SERVER_PORT", "NODEFAULTMOTD",
	"MOTD_BANNER", "KILL_IPMISMATCH", "IDLE_FROM_MSG", "HUB", 
	"WALLOPS_OPER_ONLY", "NODNS", "RANDOM_SEED", "DEFAULT_LIST_PARAM",
	"NICKNAMEHISTORYLENGTH", "NETWORK", "HOST_HIDING", "HIDDEN_HOST",
	"HIDDEN_IP", "KILLCHASETIMELIMIT", "MAXCHANNELSPERUSER", "NICKLEN",
	"AVBANLEN", "MAXBANS", "MAXSILES", "HANGONGOODLINK", "HANGONRETRYDELAY",
	"CONNECTTIMEOUT", "MAXIMUM_LINKS", "PINGFREQUENCY", "CONNECTFREQUENCY",
	"DEFAULTMAXSENDQLENGTH", "GLINEMAXUSERCOUNT", "MPATH", "RPATH", "PPATH",
	"TOS_SERVER", "TOS_CLIENT", "POLLS_PER_LOOP", "IRCD_RES_TIMEOUT",
	"IRCD_RES_RETRIES", "AUTH_TIMEOUT", "IPCHECK_CLONE_LIMIT", 
	"IPCHECK_CLONE_PERIOD", "IPCHECK_CLONE_DELAY", "CONFIG_OPERCMDS", 
	"OPLEVELS", "LOCAL_CHANNELS", "ANNOUNCE_INVITES", "HIS_SNOTICES",
	"HIS_DEBUG_OPER_ONLY", "HIS_WALLOPS", "HIS_MAP", "HIS_LINKS", 
	"HIS_TRACE", "HIS_STATS_a", "HIS_STATS_c", "HIS_STATS_d", "HIS_STATS_e",
	"HIS_STATS_f", "HIS_STATS_g", "HIS_STATS_i", "HIS_STATS_j", 
	"HIS_STATS_J", "HIS_STATS_k", "HIS_STATS_l", "HIS_STATS_L",
	"HIS_STATS_m", "HIS_STATS_M", "HIS_STATS_o", "HIS_STATS_p",
	"HIS_STATS_q", "HIS_STATS_r", "HIS_STATS_R", "HIS_STATS_t",
	"HIS_STATS_T", "HIS_STATS_u", "HIS_STATS_U", "HIS_STATS_v",
	"HIS_STATS_v", "HIS_STATS_w", "HIS_STATS_x", "HIS_STATS_z",
	"HIS_WHOIS_SERVERNAME", "HIS_WHOIS_IDLETIME", "HIS_WHOIS_LOCALCHAN",
	"HIS_WHO_SERVERNAME", "HIS_WHO_HOPCOUNT"," HIS_BANWHO", "HIS_KILLWHO",
	"HIS_REWRITE", "HIS_REMOTE", "HIS_NETSPLIT", "HIS_SERVERNAME", 
	"HIS_SERVERINFO", "HIS_URLSERVERS"
	]
deprecated_features = [ 
			"VIRTUAL_HOST",
			]

# [ "old feature" => ( local oper priv, global oper priv ) ]
# None means don't add this
feature_to_priv = {
	"UNLIMIT_OPER_QUERY" : ("unlimit_query","unlimit_query"),
	"OPER_WALK_THROUGH_LMODES" : (None, "walk_lchan"),
	"NO_OPER_DEOP_LCHAN" : (None, "deop_lchan"),
	}

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
		if user!="*":
			print '\thost = "%s@*";' % qstr(user)
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
	iline,ip,password,hostname,dummy,clss = parts
	for i in [0,1]:
		mask = [ip,hostname][i]
		# Ignore things that aren't masks
		if "." not in mask and "*" not in mask and "@" not in mask:
			continue
		if "@" in mask:
			user,host = split(mask,"@")
		else:
			user,host = "",mask
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
		if user!="":
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
	if parts[4].strip()!="":
		connects[name]["port"]=parts[4]
	connects[name]["class"]=parts[5]

def do_qline(parts):
	print "Quarintine {"
	print '\t"%s" = "%s";' % (qstr(parts[1]),qstr(parts[2]))
	print "}"

def do_oline(parts):
	opers.append(parts)

cvtmap = {
	'M': ('General', ('name', 'vhost', 'description', '-', '!numeric'), ''),
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
	'O': do_oline,
	'o': do_oline,
	'Q': ('Quarintine', ('channel','reason', '', '', ''), ''),
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
		# This field is ignored
		if parts[idx]=="-":
			continue
		if len(parts[idx]) and not len(item):
			sys.stderr.write("WARNING: Unknown field %i on line %i\n" % (idx,lno))
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

if len(opers):
	for i in opers:
		print 'Operator {'
		print '\tname = "%s";' % qstr(i[3])
		print '\thost = "%s";' % qstr(i[1])
		print '\tpassword = "%s";' % qstr(i[2])
		print '\tclass = "%s";' % qstr(i[5])
		if i[0]=='O':
			print '\tlocal = no;'
		else:
			print '\tlocal = yes;'
		for j in feats:
			if (j[0].startswith("LOCOP_") and i[0]=='o'):
				print "#",i
				if j[1].lower()=="true":
					print '\t%s = yes;'% (j[0][6:].lower())
				else:
					print '\t%s = no;' % (j[0][6:].lower())
			if (j[0].startswith("OPER_") and i[0]=='O'):
				if j[1].lower()=="true":
					print '\t%s = yes;'% (j[0][5:].lower())
				else:
					print '\t%s = no;' % (j[0][5:].lower())
			if feature_to_priv.has_key(j[0]):
				if i[0]=="o" and feature_to_priv[j[0]][0]:
					if j[1].lower()=="true":
						print '\t%s = yes;' % feature_to_priv[j[0]][0]
					else:
						print '\t%s = yes;' % feature_to_priv[j[0]][0]
				if i[0]=="O" and feature_to_priv[j[0]][1]:
					if j[1].lower()=="true":
						print '\t%s = yes;' % feature_to_priv[j[0]][1]
					else:
						print '\t%s = yes;' % feature_to_priv[j[0]][1]
		print '};'
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
		if connects[i].has_key("port"):
			print "\tport = %s;" % connects[i]["port"]
		print "\tclass = \"%s\";" % qstr(connects[i]["class"])
		if connects[i].has_key("hub"):
			print "\thub = \"%s\";" % qstr(connects[i]["hub"])
		else:
			print "\tleaf;"
		if not connects[i].has_key("port"):
			print "# You can now specify ports without implying autoconnect"
			print "#\tport = 4400;"
			print "\tautoconnect = no;"
			sys.stderr.write("NOTE: You should add a port for \"%s\", autoconnect is now specified seperately\n" % qstr(connects[i]["name"]))
		print "};"
		print

if len(feats):
	print "features {"
	for (name, value) in feats:
		if name in useable_features:
			print "\t\"%s\" = \"%s\";" % (qstr(name), qstr(value))
		else:
			if feature_to_priv.has_key(name):
				print '# Option converted to privilege "%s"' % \
					qstr(feature_to_priv[name][1])
			elif name.startswith("LOCOP_"):
				print "# Option converted to locop privilege"
			elif name.startswith("OPER_"):
				print "# Option converted to oper privilege"
			elif name in deprecated_features:
				print "# Option is deprecated"
			else:
				print "# Unknown option"
				sys.stderr.write("WARNING: Unknown option \"%s\"\n" % qstr(name))
			print "#\t\"%s\" = \"%s\";" % (qstr(name), qstr(value))
	print "};"
	print
