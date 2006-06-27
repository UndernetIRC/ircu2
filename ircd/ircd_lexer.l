/*
 * ircd_lexer.l: A lexical scanner for ircd config files.
 * This is part of ircu, an Internet Relay Chat server.
 * Copyright 2006 Michael Poole
 *
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

%option never-interactive case-insensitive warn nodefault nounput yylineno

%{

#ifndef YY_FATAL_ERROR
# define YY_FATAL_ERROR(MSG) fprintf(stderr, MSG)
#endif

#ifndef YY_NEW_FILE
# define YY_NEW_FILE
#endif

#include "config.h"
#include "ircd_alloc.h"
#include "ircd_string.h"
#include "ircd_parser.h"

void
init_lexer(const char *configfile)
{
  yyin = fopen(configfile, "r");
  if (yyin == NULL)
  {
    YY_FATAL_ERROR("Could not open the configuration file.");
  }
  YY_NEW_FILE;
}

%}

%%

\"[^"\n]+[\"\n] {yytext[yyleng-1] = 0; DupString(yylval.text, yytext+1); return QSTRING;}
[0-9]+		{yylval.num = strtoul(yytext, NULL, 10); return NUMBER;}
[ \t\r\n]+	;
#.*		;

ADMIN		return ADMIN;
ADMINISTRATOR	return ADMIN;
APASS_OPMODE	return TPRIV_APASS_OPMODE;
ALL		return ALL;
AUTO		return AUTOCONNECT;
AUTOCONNECT	return AUTOCONNECT;
B		return BYTES;
BADCHAN		return TPRIV_BADCHAN;
BYTES		return BYTES;
CHANNEL		return CHANNEL;
CHAN_LIMIT	return TPRIV_CHAN_LIMIT;
CLASS		return CLASS;
CLIENT		return CLIENT;
CONNECT		return CONNECT;
CONNECTFREQ	return CONNECTFREQ;
CONTACT		return CONTACT;
CRULE		return CRULE;
DAYS		return DAYS;
DECADES		return DECADES;
DEOP_LCHAN	return TPRIV_DEOP_LCHAN;
DESCRIPTION	return DESCRIPTION;
DIE		return TPRIV_DIE;
DISPLAY		return TPRIV_DISPLAY;
FAST		return FAST;
FEATURES	return FEATURES;
FILE		return TFILE;
FORCE_LOCAL_OPMODE	return TPRIV_FORCE_LOCAL_OPMODE;
FORCE_OPMODE	return TPRIV_FORCE_OPMODE;
GB		return GBYTES;
GBYTES		return GBYTES;
GENERAL		return GENERAL;
GIGABYTES	return GBYTES;
GLINE		return TPRIV_GLINE;
HIDDEN		return HIDDEN;
HOST		return HOST;
HOURS		return HOURS;
HUB		return HUB;
IAUTH		return IAUTH;
IP		return IP;
JUPE		return JUPE;
KB		return KBYTES;
KBYTES		return KBYTES;
KILOBYTES	return KBYTES;
KILL		return KILL;
LEAF		return LEAF;
LIST_CHAN	return TPRIV_LIST_CHAN;
LOCAL		return LOCAL;
LOCAL_BADCHAN	return TPRIV_LOCAL_BADCHAN;
LOCAL_GLINE	return TPRIV_LOCAL_GLINE;
LOCAL_JUPE	return TPRIV_LOCAL_JUPE;
LOCAL_OPMODE	return TPRIV_LOCAL_OPMODE;
LOCATION	return LOCATION;
MASK		return MASK;
MAXHOPS		return MAXHOPS;
MAXLINKS	return MAXLINKS;
MB		return MBYTES;
MBYTES		return MBYTES;
MEGABYTES	return MBYTES;
MINUTES		return MINUTES;
MODE_LCHAN	return TPRIV_MODE_LCHAN;
MONTHS		return MONTHS;
MOTD		return MOTD;
NAME		return NAME;
NICK		return NICK;
NO		return NO;
NUMERIC		return NUMERIC;
OPER		return OPER;
OPERATOR	return OPER;
OPMODE		return TPRIV_OPMODE;
PASS		return PASS;
PASSWORD	return PASS;
PINGFREQ	return PINGFREQ;
PORT		return PORT;
PREPEND		return PREPEND;
PROGRAM		return PROGRAM;
PROPAGATE	return TPRIV_PROPAGATE;
PSEUDO		return PSEUDO;
QUARANTINE	return QUARANTINE;
REAL		return REAL;
REALNAME	return REAL;
REASON		return REASON;
REHASH		return TPRIV_REHASH;
RESTART		return TPRIV_RESTART;
RULE		return RULE;
SECONDS		return SECONDS;
SEE_CHAN	return TPRIV_SEE_CHAN;
SEE_OPERS	return TPRIV_SEE_OPERS;
SENDQ		return SENDQ;
SERVER		return SERVER;
SET		return TPRIV_SET;
SHOW_ALL_INVIS	return TPRIV_SHOW_ALL_INVIS;
SHOW_INVIS	return TPRIV_SHOW_INVIS;
TIMEOUT		return TIMEOUT;
TB		return TBYTES;
TBYTES		return TBYTES;
TERABYTES	return TBYTES;
UNLIMIT_QUERY	return TPRIV_UNLIMIT_QUERY;
USERMODE	return USERMODE;
USERNAME	return USERNAME;
UWORLD		return UWORLD;
VHOST		return VHOST;
WALK_LCHAN	return TPRIV_WALK_LCHAN;
WEEKS		return WEEKS;
WIDE_GLINE	return TPRIV_WIDE_GLINE;
WHOX		return TPRIV_WHOX;
YEARS		return YEARS;
YES		return YES;

. return yytext[0];
