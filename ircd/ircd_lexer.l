/*
 * ircd_parser.y: A yacc/bison parser for ircd config files.
 * This is part of ircu, an Internet Relay Chat server.
 * The contents of this file are Copyright(C) 2001 by Andrew Miller, the
 * ircd-hybrid team and the ircu team.
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
 *  USA.
 * $Id$
 */

%{
#include <unistd.h>
#include <stdio.h>
#include "ircd.h"
#include "y.tab.h"

extern int lineno;

void
init_lexer(void)
{
  yyin = fopen(configfile, "r");
  if (yyin == NULL)
    yy_fatal_error("Could not open the configuration file.");
  YY_NEW_FILE;
  lineno = 1;
}

%}
%option noyywrap
%option case-insensitive
%option nounput


WHITE [ \t\r]+
SHCOMMENT #[^\n]*
NUMBER [0-9]+
QSTRING \"[^"\n]+[\"\n]
%%

{QSTRING} {yytext[yyleng-1] = 0; yylval.text = yytext+1; return QSTRING;}
{NUMBER} {yylval.num = strtoul(yytext, NULL, 10); return NUMBER;}
{WHITE} ;
{SHCOMMENT} ;

admin return ADMIN;
administrator return ADMIN;
general return GENERAL;
location return LOCATION;
contact return CONTACT;
connect return CONNECT;
class return CLASS;
pingfreq return PINGFREQ;
connectfreq return CONNECTFREQ;
maxlinks return MAXLINKS;
sendq return SENDQ;
name return NAME;
host return HOST;
password return PASS;
pass return PASS;
seconds return SECONDS;
minutes return MINUTES;
hours return HOURS;
days return DAYS;
weeks return WEEKS;
months return MONTHS;
years return YEARS;
decades return DECADES;
bytes return BYTES;
b return BYTES;
kbytes return KBYTES;
kilobytes return KBYTES;
kb return KBYTES;
mbytes return MBYTES;
megabytes return MBYTES;
mb return MBYTES;
gbytes return GBYTES;
gigabytes return GBYTES;
gb return GBYTES;
tbytes return TBYTES;
terabytes return TBYTES;
tb return TBYTES;
port return PORT;
server return SERVER;
yes return YES;
no return NO;
hub return HUB;
leaf return LEAF;
uworld return UWORLD;
operator return OPER;
oper return OPER;
local return LOCAL;
vhost return VHOST;
mask return MASK;
hidden return HIDDEN;
motd return MOTD;
numeric return NUMERIC;
nick return NICK;
jupe return JUPE;
description return DESCRIPTION;
client return CLIENT;
real return REAL;
realname return REAL;
reason return REASON;
file return TFILE;
rule return RULE;
all return ALL;
ip return IP;
crule return CRULE;
kill return KILL;
quarantine return QUARANTINE;
iauth return IAUTH;
timeout return TIMEOUT;
features return FEATURES;
channel return CHANNEL;
chan_limit return TPRIV_CHAN_LIMIT;
mode_lchan return TPRIV_MODE_LCHAN;
deop_lchan return TPRIV_DEOP_LCHAN;
walk_lchan return TPRIV_WALK_LCHAN;
local_kill return TPRIV_LOCAL_KILL;
rehash return TPRIV_REHASH;
restart return TPRIV_RESTART;
die return TPRIV_DIE;
gline return TPRIV_GLINE;
local_gline return TPRIV_LOCAL_GLINE;
local_jupe return TPRIV_LOCAL_JUPE;
opmode return TPRIV_OPMODE;
set return TPRIV_SET;
whox return TPRIV_WHOX;
badchan return TPRIV_BADCHAN;
local_badchan return TPRIV_LOCAL_BADCHAN;
see_chan return TPRIV_SEE_CHAN;
show_invis return TPRIV_SHOW_INVIS;
show_all_invis return TPRIV_SHOW_ALL_INVIS;
propagate return TPRIV_PROPAGATE;
unlimit_query return TPRIV_UNLIMIT_QUERY;
display return TPRIV_DISPLAY;
see_opers return TPRIV_SEE_OPERS;
wide_gline return TPRIV_WIDE_GLINE;
force_opmode return TPRIV_FORCE_OPMODE;
force_local_opmode return TPRIV_FORCE_LOCAL_OPMODE;
pseudo return PSEUDO;
prepend return PREPEND;
usermode return USERMODE;
\n lineno++;
. return yytext[0];
