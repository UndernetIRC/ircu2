/*
 * ircd_parser.y: A yacc/bison parser for ircd config files.
 * This is part of ircu, an Internet Relay Chat server.
 * The contents of this file are Copyright 2001 Diane Bruce,
 * Andrew Miller, the ircd-hybrid team and the ircu team.
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

#include "config.h"
#include "s_conf.h"
#include "class.h"
#include "client.h"
#include "crule.h"
#include "ircd_features.h"
#include "fileio.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "listener.h"
#include "match.h"
#include "motd.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "parse.h"
#include "res.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#define MAX_STRINGS 80 /* Maximum number of feature params. */
  extern struct LocalConf   localConf;
  extern struct DenyConf*   denyConfList;
  extern struct CRuleConf*  cruleConfList;
  extern struct ServerConf* serverConfList;
  extern struct s_map*      GlobalServiceMapList;
  extern struct qline*      GlobalQuarantineList;

  int yylex(void);
  void lexer_include(const char *filename);

  /* Now all the globals we need :/... */
  static int tping, tconn, maxlinks, sendq, port, invert, stringno, flags;
  static char *name, *pass, *host, *ip, *username, *origin, *hub_limit;
  static char *stringlist[MAX_STRINGS];
  static struct ConnectionClass *c_class;
  static struct DenyConf *dconf;
  static struct s_map *smap;
  static struct Privs privs;
  static struct Privs privs_dirty;

#define parse_error yyserror

enum ConfigBlock
{
  BLOCK_ADMIN,
  BLOCK_CLASS,
  BLOCK_CLIENT,
  BLOCK_CONNECT,
  BLOCK_CRULE,
  BLOCK_FEATURES,
  BLOCK_GENERAL,
  BLOCK_IAUTH,
  BLOCK_INCLUDE,
  BLOCK_JUPE,
  BLOCK_KILL,
  BLOCK_MOTD,
  BLOCK_OPER,
  BLOCK_PORT,
  BLOCK_PSEUDO,
  BLOCK_QUARANTINE,
  BLOCK_UWORLD,
  BLOCK_LAST_BLOCK
};

struct ConfigBlocks
{
  struct ConfigBlocks *cb_parent;
  unsigned long cb_allowed;
  char cb_fname[1];
};

static struct ConfigBlocks *includes;

static int
permitted(enum ConfigBlock type, int warn)
{
  static const char *block_names[BLOCK_LAST_BLOCK] = {
    "Admin", "Class", "Client", "Connect", "CRule", "Features",
    "General", "IAuth", "Include", "Jupe", "Kill", "Motd", "Oper",
    "Port", "Pseudo", "Quarantine", "UWorld",
  };

  if (!includes)
    return 1;
  if (includes->cb_allowed & (1 << type))
    return 1;
  if (warn)
  {
    /* Unfortunately, flex's yylineno is hosed for included files, so
     * do not try to use it.
     */
    yywarning("Forbidden '%s' block at %s.", block_names[type],
              includes->cb_fname);
  }
  return 0;
}

%}

%token <text> QSTRING
%token <num> NUMBER

%token GENERAL
%token ADMIN
%token LOCATION
%token CONTACT
%token CONNECT
%token CLASS
%token PINGFREQ
%token CONNECTFREQ
%token MAXLINKS
%token MAXHOPS
%token SENDQ
%token NAME
%token HOST
%token IP
%token USERNAME
%token PASS
%token LOCAL
%token SECONDS
%token MINUTES
%token HOURS
%token DAYS
%token WEEKS
%token MONTHS
%token YEARS
%token DECADES
%token BYTES
%token KBYTES
%token MBYTES
%token GBYTES
%token TBYTES
%token SERVER
%token PORT
%token MASK
%token HUB
%token LEAF
%token UWORLD
%token YES
%token NO
%token OPER
%token VHOST
%token HIDDEN
%token MOTD
%token JUPE
%token NICK
%token NUMERIC
%token DESCRIPTION
%token CLIENT
%token KILL
%token CRULE
%token REAL
%token REASON
%token TFILE
%token RULE
%token ALL
%token FEATURES
%token QUARANTINE
%token PSEUDO
%token PREPEND
%token USERMODE
%token IAUTH
%token FAST
%token AUTOCONNECT
%token PROGRAM
%token INCLUDE
%token LINESYNC
%token FROM
%token TEOF
/* and now a lot of privileges... */
%token TPRIV_CHAN_LIMIT TPRIV_MODE_LCHAN TPRIV_DEOP_LCHAN TPRIV_WALK_LCHAN
%token TPRIV_LOCAL_KILL TPRIV_REHASH TPRIV_RESTART TPRIV_DIE
%token TPRIV_GLINE TPRIV_LOCAL_GLINE TPRIV_LOCAL_JUPE TPRIV_LOCAL_BADCHAN
%token TPRIV_LOCAL_OPMODE TPRIV_OPMODE TPRIV_SET TPRIV_WHOX TPRIV_BADCHAN
%token TPRIV_SEE_CHAN TPRIV_SHOW_INVIS TPRIV_SHOW_ALL_INVIS TPRIV_PROPAGATE
%token TPRIV_UNLIMIT_QUERY TPRIV_DISPLAY TPRIV_SEE_OPERS TPRIV_WIDE_GLINE
%token TPRIV_FORCE_OPMODE TPRIV_FORCE_LOCAL_OPMODE TPRIV_APASS_OPMODE
%token TPRIV_LIST_CHAN
/* and some types... */
%type <num> sizespec
%type <num> timespec timefactor factoredtimes factoredtime
%type <num> expr yesorno privtype
%type <num> blocklimit blocktypes blocktype
%left '+' '-'
%left '*' '/'

%union{
 char *text;
 int num;
}

%%
/* Blocks in the config file... */
blocks: blocks block | block;
block: adminblock | generalblock | classblock | connectblock |
       uworldblock | operblock | portblock | jupeblock | clientblock |
       killblock | cruleblock | motdblock | featuresblock | quarantineblock |
       pseudoblock | iauthblock | includeblock | error ';';

/* The timespec, sizespec and expr was ripped straight from
 * ircd-hybrid-7. */
timespec: expr | factoredtimes;

factoredtimes: factoredtimes factoredtime
{
  $$ = $1 + $2;
} | factoredtime;

factoredtime: expr timefactor
{
  $$ = $1 * $2;
};

timefactor: SECONDS { $$ = 1; }
| MINUTES { $$ = 60; }
| HOURS { $$ = 60 * 60; }
| DAYS { $$ = 60 * 60 * 24; }
| WEEKS { $$ = 60 * 60 * 24 * 7; }
| MONTHS { $$ = 60 * 60 * 24 * 7 * 4; }
| YEARS { $$ = 60 * 60 * 24 * 365; }
| DECADES { $$ = 60 * 60 * 24 * 365 * 10; };


sizespec:	expr	{
			$$ = $1;
		}
		| expr BYTES  { 
			$$ = $1;
		}
		| expr KBYTES {
			$$ = $1 * 1024;
		}
		| expr MBYTES {
			$$ = $1 * 1024 * 1024;
		}
		| expr GBYTES {
			$$ = $1 * 1024 * 1024 * 1024;
		}
		| expr TBYTES {
			$$ = $1 * 1024 * 1024 * 1024;
		}
		;

/* this is an arithmetic expression */
expr: NUMBER
		{ 
			$$ = $1;
		}
		| expr '+' expr { 
			$$ = $1 + $3;
		}
		| expr '-' expr { 
			$$ = $1 - $3;
		}
		| expr '*' expr { 
			$$ = $1 * $3;
		}
		| expr '/' expr { 
			$$ = $1 / $3;
		}
/* leave this out until we find why it makes BSD yacc dump core -larne
		| '-' expr  %prec NEG {
			$$ = -$2;
		} */
		| '(' expr ')' {
			$$ = $2;
		}
		;

jupeblock: JUPE '{' {
  (void)permitted(BLOCK_JUPE, 1);
} jupeitems '}' ';' ;
jupeitems: jupeitem jupeitems | jupeitem;
jupeitem: jupenick;
jupenick: NICK '=' QSTRING ';'
{
  if (permitted(BLOCK_JUPE, 0))
  {
    addNickJupes($3);
    MyFree($3);
  }
};

generalblock: GENERAL
{
  if (permitted(BLOCK_GENERAL, 1))
  {
    /* Zero out the vhost addresses, in case they were removed. */
    memset(&VirtualHost_v4.addr, 0, sizeof(VirtualHost_v4.addr));
    memset(&VirtualHost_v6.addr, 0, sizeof(VirtualHost_v6.addr));
  }
} '{' generalitems '}' ';' {
  if (localConf.name == NULL)
    parse_error("Your General block must contain a name.");
  if (localConf.numeric == 0)
    parse_error("Your General block must contain a numeric (between 1 and 4095).");
};
generalitems: generalitem generalitems | generalitem;
generalitem: generalnumeric | generalname | generalvhost | generaldesc;
generalnumeric: NUMERIC '=' NUMBER ';'
{
  if (!permitted(BLOCK_GENERAL, 0))
    ;
  else if (localConf.numeric == 0)
    localConf.numeric = $3;
  else if (localConf.numeric != $3)
    parse_error("Redefinition of server numeric %i (%i)", $3,
    		localConf.numeric);
};

generalname: NAME '=' QSTRING ';'
{
  if (!permitted(BLOCK_GENERAL, 0))
    MyFree($3);
  else if (localConf.name == NULL)
    localConf.name = $3;
  else
  {
    if (strcmp(localConf.name, $3))
      parse_error("Redefinition of server name %s (%s)", $3,
                  localConf.name);
    MyFree($3);
  }
};

generaldesc: DESCRIPTION '=' QSTRING ';'
{
  if (!permitted(BLOCK_GENERAL, 0))
    MyFree($3);
  else
  {
    MyFree(localConf.description);
    localConf.description = $3;
    ircd_strncpy(cli_info(&me), $3, REALLEN);
  }
};

generalvhost: VHOST '=' QSTRING ';'
{
  struct irc_in_addr addr;
  if (!permitted(BLOCK_GENERAL, 0))
    ;
  else if (!strcmp($3, "*")) {
    /* This traditionally meant bind to all interfaces and connect
     * from the default. */
  } else if (!ircd_aton(&addr, $3))
    parse_error("Invalid virtual host '%s'.", $3);
  else if (irc_in_addr_is_ipv4(&addr))
    memcpy(&VirtualHost_v4.addr, &addr, sizeof(addr));
  else
    memcpy(&VirtualHost_v6.addr, &addr, sizeof(addr));
  MyFree($3);
};

adminblock: ADMIN
{
  if (permitted(BLOCK_ADMIN, 1))
  {
    MyFree(localConf.location1);
    MyFree(localConf.location2);
    MyFree(localConf.contact);
    localConf.location1 = localConf.location2 = localConf.contact = NULL;
  }
}
'{' adminitems '}' ';'
{
  if (localConf.location1 == NULL)
    DupString(localConf.location1, "");
  if (localConf.location2 == NULL)
    DupString(localConf.location2, "");
  if (localConf.contact == NULL)
    DupString(localConf.contact, "");
};
adminitems: adminitems adminitem | adminitem;
adminitem: adminlocation | admincontact;
adminlocation: LOCATION '=' QSTRING ';'
{
  if (!permitted(BLOCK_ADMIN, 0))
    MyFree($3);
  else if (localConf.location1 == NULL)
    localConf.location1 = $3;
  else if (localConf.location2 == NULL)
    localConf.location2 = $3;
  else /* Otherwise just drop it. -A1kmm */
    MyFree($3);
};
admincontact: CONTACT '=' QSTRING ';'
{
  if (!permitted(BLOCK_ADMIN, 0))
    MyFree($3);
  else
  {
    MyFree(localConf.contact);
    localConf.contact = $3;
  }
};

classblock: CLASS {
  tping = 90;
} '{' classitems '}' ';'
{
  if (!permitted(BLOCK_CLASS, 1))
    ;
  else if (name != NULL)
  {
    struct ConnectionClass *c_class;
    add_class(name, tping, tconn, maxlinks, sendq);
    c_class = find_class(name);
    MyFree(c_class->default_umode);
    c_class->default_umode = pass;
    memcpy(&c_class->privs, &privs, sizeof(c_class->privs));
    memcpy(&c_class->privs_dirty, &privs_dirty, sizeof(c_class->privs_dirty));
  }
  else {
   parse_error("Missing name in class block");
  }
  name = NULL;
  pass = NULL;
  tconn = 0;
  maxlinks = 0;
  sendq = 0;
  memset(&privs, 0, sizeof(privs));
  memset(&privs_dirty, 0, sizeof(privs_dirty));
};
classitems: classitem classitems | classitem;
classitem: classname | classpingfreq | classconnfreq | classmaxlinks |
           classsendq | classusermode | priv;
classname: NAME '=' QSTRING ';'
{
  MyFree(name);
  name = $3;
};
classpingfreq: PINGFREQ '=' timespec ';'
{
  tping = $3;
};
classconnfreq: CONNECTFREQ '=' timespec ';'
{
  tconn = $3;
};
classmaxlinks: MAXLINKS '=' expr ';'
{
  maxlinks = $3;
};
classsendq: SENDQ '=' sizespec ';'
{
  sendq = $3;
};
classusermode: USERMODE '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};

connectblock: CONNECT
{
 maxlinks = 65535;
 flags = CONF_AUTOCONNECT;
} '{' connectitems '}' ';'
{
 struct ConfItem *aconf = NULL;
 if (!permitted(BLOCK_CONNECT, 1))
   ;
 else if (name == NULL)
  parse_error("Missing name in connect block");
 else if (pass == NULL)
  parse_error("Missing password in connect block");
 else if (host == NULL)
  parse_error("Missing host in connect block");
 else if (strchr(host, '*') || strchr(host, '?'))
  parse_error("Invalid host '%s' in connect block", host);
 else if (c_class == NULL)
  parse_error("Missing or non-existent class in connect block");
 else {
   aconf = make_conf(CONF_SERVER);
   aconf->name = name;
   aconf->origin_name = origin;
   aconf->passwd = pass;
   aconf->conn_class = c_class;
   aconf->address.port = port;
   aconf->host = host;
   aconf->maximum = maxlinks;
   aconf->hub_limit = hub_limit;
   aconf->flags = flags;
   lookup_confhost(aconf);
 }
 if (!aconf) {
   MyFree(name);
   MyFree(pass);
   MyFree(host);
   MyFree(origin);
   MyFree(hub_limit);
 }
 name = pass = host = origin = hub_limit = NULL;
 c_class = NULL;
 port = flags = 0;
};
connectitems: connectitem connectitems | connectitem;
connectitem: connectname | connectpass | connectclass | connecthost
              | connectport | connectvhost | connectleaf | connecthub
              | connecthublimit | connectmaxhops | connectauto;
connectname: NAME '=' QSTRING ';'
{
 MyFree(name);
 name = $3;
};
connectpass: PASS '=' QSTRING ';'
{
 MyFree(pass);
 pass = $3;
};
connectclass: CLASS '=' QSTRING ';'
{
 c_class = find_class($3);
 if (!c_class)
  parse_error("No such connection class '%s' for Connect block", $3);
 MyFree($3);
};
connecthost: HOST '=' QSTRING ';'
{
 MyFree(host);
 host = $3;
};
connectport: PORT '=' NUMBER ';'
{
 port = $3;
};
connectvhost: VHOST '=' QSTRING ';'
{
 MyFree(origin);
 origin = $3;
};
connectleaf: LEAF ';'
{
 maxlinks = 0;
};
connecthub: HUB ';'
{
 MyFree(hub_limit);
 DupString(hub_limit, "*");
};
connecthublimit: HUB '=' QSTRING ';'
{
 MyFree(hub_limit);
 hub_limit = $3;
};
connectmaxhops: MAXHOPS '=' expr ';'
{
  maxlinks = $3;
};
connectauto: AUTOCONNECT '=' YES ';' { flags |= CONF_AUTOCONNECT; }
 | AUTOCONNECT '=' NO ';' { flags &= ~CONF_AUTOCONNECT; };

uworldblock: UWORLD '{' {
  (void)permitted(BLOCK_UWORLD, 1);
}  uworlditems '}' ';';
uworlditems: uworlditem uworlditems | uworlditem;
uworlditem: uworldname;
uworldname: NAME '=' QSTRING ';'
{
  if (permitted(BLOCK_UWORLD, 0))
    make_conf(CONF_UWORLD)->host = $3;
};

operblock: OPER '{' operitems '}' ';'
{
  struct ConfItem *aconf = NULL;
  if (!permitted(BLOCK_OPER, 1))
    ;
  else if (name == NULL)
    parse_error("Missing name in operator block");
  else if (pass == NULL)
    parse_error("Missing password in operator block");
  else if (host == NULL)
    parse_error("Missing host in operator block");
  else if (c_class == NULL)
    parse_error("Invalid or missing class in operator block");
  else {
    aconf = make_conf(CONF_OPERATOR);
    aconf->name = name;
    aconf->passwd = pass;
    conf_parse_userhost(aconf, host);
    aconf->conn_class = c_class;
    memcpy(&aconf->privs, &privs, sizeof(aconf->privs));
    memcpy(&aconf->privs_dirty, &privs_dirty, sizeof(aconf->privs_dirty));
    if (!FlagHas(&privs_dirty, PRIV_PROPAGATE)
        && !FlagHas(&c_class->privs_dirty, PRIV_PROPAGATE))
      parse_error("Operator block for %s and class %s have no LOCAL setting", name, c_class->cc_name);
  }
  if (!aconf) {
    MyFree(name);
    MyFree(pass);
    MyFree(host);
  }
  name = pass = host = NULL;
  c_class = NULL;
  memset(&privs, 0, sizeof(privs));
  memset(&privs_dirty, 0, sizeof(privs_dirty));
};
operitems: operitem | operitems operitem;
operitem: opername | operpass | operhost | operclass | priv;
opername: NAME '=' QSTRING ';'
{
  MyFree(name);
  name = $3;
};
operpass: PASS '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};
operhost: HOST '=' QSTRING ';'
{
 MyFree(host);
 if (!strchr($3, '@'))
 {
   int uh_len;
   host = (char*) MyMalloc((uh_len = strlen($3)+3));
   ircd_snprintf(0, host, uh_len, "*@%s", $3);
   MyFree($3);
 }
 else
   host = $3;
};
operclass: CLASS '=' QSTRING ';'
{
 c_class = find_class($3);
 if (!c_class)
  parse_error("No such connection class '%s' for Operator block", $3);
 MyFree($3);
};

priv: privtype '=' yesorno ';'
{
  FlagSet(&privs_dirty, $1);
  if (($3 == 1) ^ invert)
    FlagSet(&privs, $1);
  else
    FlagClr(&privs, $1);
  invert = 0;
};

privtype: TPRIV_CHAN_LIMIT { $$ = PRIV_CHAN_LIMIT; } |
          TPRIV_MODE_LCHAN { $$ = PRIV_MODE_LCHAN; } |
          TPRIV_DEOP_LCHAN { $$ = PRIV_DEOP_LCHAN; } |
          TPRIV_WALK_LCHAN { $$ = PRIV_WALK_LCHAN; } |
          KILL { $$ = PRIV_KILL; } |
          TPRIV_LOCAL_KILL { $$ = PRIV_LOCAL_KILL; } |
          TPRIV_REHASH { $$ = PRIV_REHASH; } |
          TPRIV_RESTART { $$ = PRIV_RESTART; } |
          TPRIV_DIE { $$ = PRIV_DIE; } |
          TPRIV_GLINE { $$ = PRIV_GLINE; } |
          TPRIV_LOCAL_GLINE { $$ = PRIV_LOCAL_GLINE; } |
          JUPE { $$ = PRIV_JUPE; } |
          TPRIV_LOCAL_JUPE { $$ = PRIV_LOCAL_JUPE; } |
          TPRIV_LOCAL_OPMODE { $$ = PRIV_LOCAL_OPMODE; } |
          TPRIV_OPMODE { $$ = PRIV_OPMODE; }|
          TPRIV_SET { $$ = PRIV_SET; } |
          TPRIV_WHOX { $$ = PRIV_WHOX; } |
          TPRIV_BADCHAN { $$ = PRIV_BADCHAN; } |
          TPRIV_LOCAL_BADCHAN { $$ = PRIV_LOCAL_BADCHAN; } |
          TPRIV_SEE_CHAN { $$ = PRIV_SEE_CHAN; } |
          TPRIV_SHOW_INVIS { $$ = PRIV_SHOW_INVIS; } |
          TPRIV_SHOW_ALL_INVIS { $$ = PRIV_SHOW_ALL_INVIS; } |
          TPRIV_PROPAGATE { $$ = PRIV_PROPAGATE; } |
          TPRIV_UNLIMIT_QUERY { $$ = PRIV_UNLIMIT_QUERY; } |
          TPRIV_DISPLAY { $$ = PRIV_DISPLAY; } |
          TPRIV_SEE_OPERS { $$ = PRIV_SEE_OPERS; } |
          TPRIV_WIDE_GLINE { $$ = PRIV_WIDE_GLINE; } |
          TPRIV_LIST_CHAN { $$ = PRIV_LIST_CHAN; } |
          LOCAL { $$ = PRIV_PROPAGATE; invert = 1; } |
          TPRIV_FORCE_OPMODE { $$ = PRIV_FORCE_OPMODE; } |
          TPRIV_FORCE_LOCAL_OPMODE { $$ = PRIV_FORCE_LOCAL_OPMODE; } |
          TPRIV_APASS_OPMODE { $$ = PRIV_APASS_OPMODE; } ;

yesorno: YES { $$ = 1; } | NO { $$ = 0; };

/* The port block... */
portblock: PORT '{' portitems '}' ';'
{
  if (!permitted(BLOCK_PORT, 1))
    ;
  else if (port > 0 && port <= 0xFFFF)
    add_listener(port, host, pass, tconn, tping);
  else
    parse_error("Port %d is out of range", port);
  MyFree(host);
  MyFree(pass);
  host = pass = NULL;
  port = tconn = tping = 0;
};
portitems: portitem portitems | portitem;
portitem: portnumber | portvhost | portmask | portserver | porthidden;
portnumber: PORT '=' NUMBER ';'
{
  port = $3;
};

portvhost: VHOST '=' QSTRING ';'
{
  MyFree(host);
  host = $3;
};

portmask: MASK '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};

portserver: SERVER '=' YES ';'
{
  tconn = -1;
} | SERVER '=' NO ';'
{
  tconn = 0;
};

porthidden: HIDDEN '=' YES ';'
{
  tping = -1;
} | HIDDEN '=' NO ';'
{
  tping = 0;
};

clientblock: CLIENT
{
  maxlinks = 65535;
  port = 0;
}
'{' clientitems '}' ';'
{
  struct ConfItem *aconf = 0;
  struct irc_in_addr addr;
  unsigned char addrbits = 0;

  if (!permitted(BLOCK_CLIENT, 1))
    ;
  else if (!c_class)
    parse_error("Invalid or missing class in Client block");
  else if (ip && !ipmask_parse(ip, &addr, &addrbits))
    parse_error("Invalid IP address %s in Client block", ip);
  else {
    aconf = make_conf(CONF_CLIENT);
    aconf->username = username;
    aconf->host = host;
    if (ip)
      memcpy(&aconf->address.addr, &addr, sizeof(aconf->address.addr));
    else
      memset(&aconf->address.addr, 0, sizeof(aconf->address.addr));
    aconf->address.port = port;
    aconf->addrbits = addrbits;
    aconf->name = ip;
    aconf->conn_class = c_class;
    aconf->maximum = maxlinks;
    aconf->passwd = pass;
  }
  if (!aconf) {
    MyFree(username);
    MyFree(host);
    MyFree(ip);
    MyFree(pass);
  }
  host = NULL;
  username = NULL;
  c_class = NULL;
  ip = NULL;
  pass = NULL;
  port = 0;
};
clientitems: clientitem clientitems | clientitem;
clientitem: clienthost | clientip | clientusername | clientclass | clientpass | clientmaxlinks | clientport;
clienthost: HOST '=' QSTRING ';'
{
  char *sep = strchr($3, '@');
  MyFree(host);
  if (sep) {
    *sep++ = '\0';
    MyFree(username);
    DupString(host, sep);
    username = $3;
  } else {
    host = $3;
  }
};
clientip: IP '=' QSTRING ';'
{
  char *sep;
  sep = strchr($3, '@');
  MyFree(ip);
  if (sep) {
    *sep++ = '\0';
    MyFree(username);
    DupString(ip, sep);
    username = $3;
  } else {
    ip = $3;
  }
};
clientusername: USERNAME '=' QSTRING ';'
{
  MyFree(username);
  username = $3;
};
clientclass: CLASS '=' QSTRING ';'
{
  c_class = find_class($3);
  if (!c_class)
    parse_error("No such connection class '%s' for Client block", $3);
  MyFree($3);
};
clientpass: PASS '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};
clientmaxlinks: MAXLINKS '=' expr ';'
{
  maxlinks = $3;
};
clientport: PORT '=' expr ';'
{
  port = $3;
};

killblock: KILL
{
  dconf = (struct DenyConf*) MyCalloc(1, sizeof(*dconf));
} '{' killitems '}' ';'
{
  if (!permitted(BLOCK_KILL, 1))
  {
    MyFree(dconf->usermask);
    MyFree(dconf->hostmask);
    MyFree(dconf->realmask);
    MyFree(dconf->message);
    MyFree(dconf);
  }
  else if (dconf->usermask || dconf->hostmask ||dconf->realmask)
  {
    dconf->next = denyConfList;
    denyConfList = dconf;
  }
  else
  {
    MyFree(dconf->usermask);
    MyFree(dconf->hostmask);
    MyFree(dconf->realmask);
    MyFree(dconf->message);
    MyFree(dconf);
    parse_error("Kill block must match on at least one of username, host or realname");
  }
  dconf = NULL;
};
killitems: killitem killitems | killitem;
killitem: killuhost | killreal | killusername | killreasonfile | killreason;
killuhost: HOST '=' QSTRING ';'
{
  char *h;
  MyFree(dconf->hostmask);
  MyFree(dconf->usermask);
  if ((h = strchr($3, '@')) == NULL)
  {
    DupString(dconf->usermask, "*");
    dconf->hostmask = $3;
  }
  else
  {
    *h++ = '\0';
    DupString(dconf->hostmask, h);
    dconf->usermask = $3;
  }
  ipmask_parse(dconf->hostmask, &dconf->address, &dconf->bits);
};

killusername: USERNAME '=' QSTRING ';'
{
  MyFree(dconf->usermask);
  dconf->usermask = $3;
};

killreal: REAL '=' QSTRING ';'
{
 MyFree(dconf->realmask);
 dconf->realmask = $3;
};

killreason: REASON '=' QSTRING ';'
{
 dconf->flags &= ~DENY_FLAGS_FILE;
 MyFree(dconf->message);
 dconf->message = $3;
};

killreasonfile: TFILE '=' QSTRING ';'
{
 dconf->flags |= DENY_FLAGS_FILE;
 MyFree(dconf->message);
 dconf->message = $3;
};

cruleblock: CRULE
{
  tconn = CRULE_AUTO;
} '{' cruleitems '}' ';'
{
  struct CRuleNode *node = NULL;
  if (!permitted(BLOCK_CRULE, 1))
    ;
  else if (host == NULL)
    parse_error("Missing host in crule block");
  else if (pass == NULL)
    parse_error("Missing rule in crule block");
  else if ((node = crule_parse(pass)) == NULL)
    parse_error("Invalid rule '%s' in crule block", pass);
  else
  {
    struct CRuleConf *p = (struct CRuleConf*) MyMalloc(sizeof(*p));
    p->hostmask = host;
    p->rule = pass;
    p->type = tconn;
    p->node = node;
    p->next = cruleConfList;
    cruleConfList = p;
  }
  if (!node)
  {
    MyFree(host);
    MyFree(pass);
  }
  host = pass = NULL;
  tconn = 0;
};

cruleitems: cruleitem cruleitems | cruleitem;
cruleitem: cruleserver | crulerule | cruleall;

cruleserver: SERVER '=' QSTRING ';'
{
  MyFree(host);
  collapse($3);
  host = $3;
};

crulerule: RULE '=' QSTRING ';'
{
 MyFree(pass);
 pass = $3;
};

cruleall: ALL '=' YES ';'
{
 tconn = CRULE_ALL;
} | ALL '=' NO ';'
{
 tconn = CRULE_AUTO;
};

motdblock: MOTD '{' motditems '}' ';'
{
  if (permitted(BLOCK_MOTD, 1) && host != NULL && pass != NULL)
    motd_add(host, pass);
  MyFree(host);
  MyFree(pass);
  host = pass = NULL;
};

motditems: motditem motditems | motditem;
motditem: motdhost | motdfile;
motdhost: HOST '=' QSTRING ';'
{
  host = $3;
};

motdfile: TFILE '=' QSTRING ';'
{
  pass = $3;
};

featuresblock: FEATURES '{' {
  (void)permitted(BLOCK_FEATURES, 1);
} featureitems '}' ';';
featureitems: featureitems featureitem | featureitem;

featureitem: QSTRING
{
  stringlist[0] = $1;
  stringno = 1;
} '=' stringlist ';' {
  unsigned int ii;
  if (permitted(BLOCK_FEATURES, 0))
    feature_set(NULL, (const char * const *)stringlist, stringno);
  for (ii = 0; ii < stringno; ++ii)
    MyFree(stringlist[ii]);
};

stringlist: stringlist extrastring | extrastring;
extrastring: QSTRING
{
  if (stringno < MAX_STRINGS)
    stringlist[stringno++] = $1;
  else
    MyFree($1);
};

quarantineblock: QUARANTINE '{' {
  (void)permitted(BLOCK_QUARANTINE, 1);
} quarantineitems '}' ';';
quarantineitems: quarantineitems quarantineitem | quarantineitem;
quarantineitem: QSTRING '=' QSTRING ';'
{
  if (!permitted(BLOCK_QUARANTINE, 0))
  {
    MyFree($1);
    MyFree($3);
  }
  else
  {
    struct qline *qconf = MyCalloc(1, sizeof(*qconf));
    qconf->chname = $1;
    qconf->reason = $3;
    qconf->next = GlobalQuarantineList;
    GlobalQuarantineList = qconf;
  }
};

pseudoblock: PSEUDO QSTRING '{'
{
  smap = MyCalloc(1, sizeof(struct s_map));
  smap->command = $2;
}
pseudoitems '}' ';'
{
  int valid = 0;

  if (!permitted(BLOCK_PSEUDO, 1))
    ;
  else if (!smap->name)
    parse_error("Missing name in pseudo %s block", smap->command);
  else if (!smap->services)
    parse_error("Missing nick in pseudo %s block", smap->command);
  else
    valid = 1;
  if (valid && register_mapping(smap))
  {
    smap->next = GlobalServiceMapList;
    GlobalServiceMapList = smap;
  }
  else
  {
    free_mapping(smap);
  }
  smap = NULL;
};

pseudoitems: pseudoitem pseudoitems | pseudoitem;
pseudoitem: pseudoname | pseudoprepend | pseudonick | pseudoflags;
pseudoname: NAME '=' QSTRING ';'
{
  MyFree(smap->name);
  smap->name = $3;
};
pseudoprepend: PREPEND '=' QSTRING ';'
{
  MyFree(smap->prepend);
  smap->prepend = $3;
};
pseudonick: NICK '=' QSTRING ';'
{
  char *sep = strchr($3, '@');

  if (sep != NULL) {
    size_t slen = strlen($3);
    struct nick_host *nh = MyMalloc(sizeof(*nh) + slen);
    memcpy(nh->nick, $3, slen + 1);
    nh->nicklen = sep - $3;
    nh->next = smap->services;
    smap->services = nh;
  }
  MyFree($3);
};
pseudoflags: FAST ';'
{
  smap->flags |= SMAP_FAST;
};

iauthblock: IAUTH '{' iauthitems '}' ';'
{
  if (permitted(BLOCK_IAUTH, 1))
    auth_spawn(stringno, stringlist);
  while (stringno > 0)
    MyFree(stringlist[--stringno]);
};

iauthitems: iauthitem iauthitems | iauthitem;
iauthitem: iauthprogram;
iauthprogram: PROGRAM '='
{
  while (stringno > 0)
    MyFree(stringlist[--stringno]);
} stringlist ';';

includeblock: INCLUDE blocklimit QSTRING ';' {
  struct ConfigBlocks *child;

  child = MyCalloc(1, sizeof(*child) + strlen($3));
  strcpy(child->cb_fname, $3);
  child->cb_allowed = $2 & (includes ? includes->cb_allowed : ~0);
  child->cb_parent = includes;
  MyFree($3);

  if (permitted(BLOCK_INCLUDE, 1))
    lexer_include(child->cb_fname);
  else
    lexer_include(NULL);

  includes = child;
} blocks TEOF {
  struct ConfigBlocks *parent;

  parent = includes->cb_parent;
  MyFree(includes);
  includes = parent;
};

blocklimit: { $$ = ~0; } ;
blocklimit: blocktypes FROM;
blocktypes: blocktypes ',' blocktype { $$ = $1 | $3; };
blocktypes: blocktype;
blocktype: ALL { $$ = ~0; }
  | ADMIN { $$ = 1 << BLOCK_ADMIN; }
  | CLASS { $$ = 1 << BLOCK_CLASS; }
  | CLIENT { $$ = 1 << BLOCK_CLIENT; }
  | CONNECT { $$ = 1 << BLOCK_CONNECT; }
  | CRULE { $$ = 1 << BLOCK_CRULE; }
  | FEATURES { $$ = 1 << BLOCK_FEATURES; }
  | GENERAL { $$ = 1 << BLOCK_GENERAL; }
  | IAUTH { $$ = 1 << BLOCK_IAUTH; }
  | INCLUDE { $$ = 1 << BLOCK_INCLUDE; }
  | JUPE { $$ = 1 << BLOCK_JUPE; }
  | KILL { $$ = 1 << BLOCK_KILL; }
  | MOTD { $$ = 1 << BLOCK_MOTD; }
  | OPER { $$ = 1 << BLOCK_OPER; }
  | PORT { $$ = 1 << BLOCK_PORT; }
  | PSEUDO { $$ = 1 << BLOCK_PSEUDO; }
  | QUARANTINE { $$ = 1 << BLOCK_QUARANTINE; }
  | UWORLD { $$ = 1 << BLOCK_UWORLD; }
  ;
