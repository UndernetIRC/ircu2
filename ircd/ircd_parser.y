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
#include "ircd_auth.h"
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
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "support.h"
#include "sys.h"
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
  /* Now all the globals we need :/... */
  int tping, tconn, maxlinks, sendq, port, invert;
  int stringno;
  char *name, *pass, *host, *origin;
  char *stringlist[MAX_STRINGS];
  struct ConnectionClass *c_class;
  struct ConfItem *aconf;
  struct DenyConf *dconf;
  struct ServerConf *sconf;
  struct qline *qconf = NULL;
  struct s_map *smap;
  struct Privs privs;
  struct Privs privs_dirty;

static void parse_error(char *pattern,...) {
  static char error_buffer[1024];
  va_list vl;
  va_start(vl,pattern);
  ircd_vsnprintf(NULL, error_buffer, sizeof(error_buffer), pattern, vl);
  va_end(vl);
  yyerror(error_buffer);
}

%}

%token <text> QSTRING
%token <num> NUMBER
%token <text> FNAME

%token GENERAL
%token ADMIN
%token LOCATION
%token CONTACT
%token CONNECT
%token CLASS
%token CHANNEL
%token PINGFREQ
%token CONNECTFREQ
%token MAXLINKS
%token SENDQ
%token NAME
%token HOST
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
%token IP
%token FEATURES
%token QUARANTINE
%token PSEUDO
%token PREPEND
%token USERMODE
%token IAUTH
%token TIMEOUT
/* and now a lot of priviledges... */
%token TPRIV_CHAN_LIMIT TPRIV_MODE_LCHAN TPRIV_DEOP_LCHAN TPRIV_WALK_LCHAN
%token TPRIV_LOCAL_KILL TPRIV_REHASH TPRIV_RESTART TPRIV_DIE
%token TPRIV_GLINE TPRIV_LOCAL_GLINE TPRIV_LOCAL_JUPE TPRIV_LOCAL_BADCHAN
%token TPRIV_LOCAL_OPMODE TPRIV_OPMODE TPRIV_SET TPRIV_WHOX TPRIV_BADCHAN
%token TPRIV_SEE_CHAN TPRIV_SHOW_INVIS TPRIV_SHOW_ALL_INVIS TPRIV_PROPAGATE
%token TPRIV_UNLIMIT_QUERY TPRIV_DISPLAY TPRIV_SEE_OPERS TPRIV_WIDE_GLINE
%token TPRIV_FORCE_OPMODE TPRIV_FORCE_LOCAL_OPMODE
/* and some types... */
%type <num> sizespec
%type <num> timespec timefactor factoredtimes factoredtime
%type <num> expr yesorno privtype
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
       serverblock | operblock | portblock | jupeblock | clientblock |
       killblock | cruleblock | motdblock | featuresblock | quarantineblock |
       pseudoblock | iauthblock | error;

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

/* this is an arithmatic expression */
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
		| '-' expr  %prec NEG
		= {
			$$ = -$2;
		} */
		| '(' expr ')' {
			$$ = $2;
		}
		;

jupeblock: JUPE '{' jupeitems '}' ';' ;
jupeitems: jupeitem jupeitems | jupeitem;
jupeitem: jupenick | error;
jupenick: NICK '=' QSTRING
{
  addNickJupes($3);
} ';';

generalblock: GENERAL '{' generalitems '}'
{
  if (localConf.name == NULL)
    parse_error("Your General block must contain a name.");
  if (localConf.numeric == 0)
    parse_error("Your General block must contain a numeric (between 1 and 4095).");
} ';' ;
generalitems: generalitem generalitems | generalitem;
generalitem: generalnumeric | generalname | generalvhost | generaldesc | error;
generalnumeric: NUMERIC '=' NUMBER ';'
{
  if (localConf.numeric == 0)
    localConf.numeric = $3;
  else if (localConf.numeric != $3)
    parse_error("Redefinition of server numeric %i (%i)", $3,
    		localConf.numeric);
};

generalname: NAME '=' QSTRING ';'
{
  if (localConf.name == NULL)
    DupString(localConf.name, $3);
  else if (strcmp(localConf.name, $3))
    parse_error("Redefinition of server name %s (%s)", $3,
    		localConf.name);
};

generaldesc: DESCRIPTION '=' QSTRING ';'
{
  MyFree(localConf.description);
  DupString(localConf.description, $3);
  ircd_strncpy(cli_info(&me), $3, REALLEN);
};

generalvhost: VHOST '=' QSTRING ';'
{
  ircd_aton(&VirtualHost.addr, $3);
};

adminblock: ADMIN '{' adminitems '}'
{
  if (localConf.location1 == NULL)
    DupString(localConf.location1, "");
  if (localConf.location2 == NULL)
    DupString(localConf.location2, "");
  if (localConf.contact == NULL)
    DupString(localConf.contact, "");
} ';';
adminitems: adminitems adminitem | adminitem;
adminitem: adminlocation | admincontact | error;
adminlocation: LOCATION '=' QSTRING ';'
{
 if (localConf.location1 == NULL)
  DupString(localConf.location1, $3);
 else if (localConf.location2 == NULL)
  DupString(localConf.location2, $3);
 /* Otherwise just drop it. -A1kmm */
};
admincontact: CONTACT '=' QSTRING ';'
{
 if (localConf.contact != NULL)
   MyFree(localConf.contact);
 DupString(localConf.contact, $3);
};

classblock: CLASS {
  name = NULL;
  tping = 90;
  tconn = 0;
  maxlinks = 0;
  sendq = 0;
  pass = NULL;
  memset(&privs, 0, sizeof(privs));
  memset(&privs_dirty, 0, sizeof(privs_dirty));
} '{' classitems '}'
{
  if (name != NULL)
  {
    struct ConnectionClass *c_class;
    add_class(name, tping, tconn, maxlinks, sendq);
    c_class = find_class(name);
    c_class->default_umode = pass;
    memcpy(&c_class->privs, &privs, sizeof(c_class->privs));
    memcpy(&c_class->privs_dirty, &privs_dirty, sizeof(c_class->privs_dirty));
  }
  else {
   parse_error("Missing name in class block");
  }
  pass = NULL;
} ';';
classitems: classitem classitems | classitem;
classitem: classname | classpingfreq | classconnfreq | classmaxlinks |
           classsendq | classusermode | priv | error;
classname: NAME '=' QSTRING ';'
{
  MyFree(name);
  DupString(name, $3);
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
  if (pass)
    MyFree(pass);
  DupString(pass, $3);
};

connectblock: CONNECT
{
 name = pass = host = origin = NULL;
 c_class = NULL;
 port = 0;
} '{' connectitems '}'
{
 if (name != NULL && pass != NULL && host != NULL && c_class != NULL
     && !strchr(host, '*') && !strchr(host, '?'))
 {
   aconf = make_conf();
   aconf->status = CONF_SERVER;
   aconf->name = name;
   aconf->origin_name = origin;
   aconf->passwd = pass;
   aconf->conn_class = c_class;
   aconf->address.port = port;
   aconf->status = CONF_SERVER;
   aconf->host = host;
   aconf->next = GlobalConfList;
   lookup_confhost(aconf);
   GlobalConfList = aconf;
 }
 else
 {
   MyFree(name);
   MyFree(pass);
   MyFree(host);
   MyFree(origin);
   parse_error("Bad connect block");
 }
 name = pass = host = origin = NULL;
}';';
connectitems: connectitem connectitems | connectitem;
connectitem: connectname | connectpass | connectclass | connecthost
              | connectport | connectvhost | error;
connectname: NAME '=' QSTRING ';'
{
 MyFree(name);
 DupString(name, $3);
};
connectpass: PASS '=' QSTRING ';'
{
 MyFree(pass);
 DupString(pass, $3);
};
connectclass: CLASS '=' QSTRING ';'
{
 c_class = find_class($3);
};
connecthost: HOST '=' QSTRING ';'
{
 MyFree(host);
 DupString(host, $3);
};
connectport: PORT '=' NUMBER ';'
{
 port = $3;
};
connectvhost: VHOST '=' QSTRING ';'
{
 MyFree(origin);
 DupString(origin, $3);
};

serverblock: SERVER
{
 aconf = (struct ConfItem*) MyMalloc(sizeof(*aconf));
 memset(aconf, 0, sizeof(*aconf));
 aconf->status = CONF_LEAF;
} '{' serveritems '}'
{
 if (aconf->status == 0)
 {
   MyFree(aconf->host);
   MyFree(aconf->name);
   MyFree(aconf);
   aconf = NULL;
   parse_error("Bad server block");
 }
 else
 {
   aconf->next = GlobalConfList;
   GlobalConfList = aconf;
 }
} ';';
serveritems: serveritem serveritems | serveritem;
serveritem: servername | servermask | serverhub | serverleaf |
             serveruworld | error;
servername: NAME '=' QSTRING
{
 MyFree(aconf->name);
 DupString(aconf->name, $3);
} ';' ;
servermask: MASK '=' QSTRING
{
 MyFree(aconf->host);
 DupString(aconf->host, $3);
} ';' ;
/* XXX - perhaps we should do this the hybrid way in connect blocks
 * instead -A1kmm. */
serverhub: HUB '=' YES ';'
{
 aconf->status |= CONF_HUB;
 aconf->status &= ~CONF_LEAF;
}
| HUB '=' NO
{
 aconf->status &= ~CONF_HUB;
} ';'; 
serverleaf: LEAF '=' YES ';'
{
 if (!(aconf->status & CONF_HUB && aconf->status & CONF_UWORLD))
  aconf->status |= CONF_LEAF;
 else
  parse_error("Server is both leaf and a hub");
}
| LEAF '=' NO ';'
{
 aconf->status &= ~CONF_LEAF;
};
serveruworld: UWORLD '=' YES ';'
{
 aconf->status |= CONF_UWORLD;
 aconf->status &= ~CONF_LEAF;
}
| UWORLD '=' NO ';'
{
  aconf->status &= ~CONF_UWORLD;
};

operblock: OPER
{
  aconf = (struct ConfItem*) MyMalloc(sizeof(*aconf));
  memset(aconf, 0, sizeof(*aconf));
  memset(&privs, 0, sizeof(privs));
  memset(&privs_dirty, 0, sizeof(privs_dirty));
  aconf->status = CONF_OPERATOR;
} '{' operitems '}' ';'
{
  if (aconf->name != NULL && aconf->passwd != NULL && aconf->host != NULL
      && aconf->conn_class != NULL)
  {
    memcpy(&aconf->privs, &privs, sizeof(aconf->privs));
    memcpy(&aconf->privs_dirty, &privs_dirty, sizeof(aconf->privs_dirty));
    if (!PrivHas(&privs_dirty, PRIV_PROPAGATE)
        && !PrivHas(&aconf->conn_class->privs_dirty, PRIV_PROPAGATE))
      parse_error("Operator block for %s and class %s have no LOCAL setting", aconf->name, aconf->conn_class->cc_name);
    aconf->next = GlobalConfList;
    GlobalConfList = aconf;
  }
  else
  {
    log_write(LS_CONFIG, L_ERROR, 0, "operator blocks need a name, password, and host.");
    MyFree(aconf->name);
    MyFree(aconf->passwd);
    MyFree(aconf->host);
    MyFree(aconf);
    aconf = NULL;
  }
};
operitems: operitem | operitems operitem;
operitem: opername | operpass | operhost | operclass | priv | error;

opername: NAME '=' QSTRING ';'
{
  MyFree(aconf->name);
  DupString(aconf->name, $3);
};

operpass: PASS '=' QSTRING ';'
{
  MyFree(aconf->passwd);
  DupString(aconf->passwd, $3);
};

operhost: HOST '=' QSTRING ';'
{
 MyFree(aconf->host);
 if (!strchr($3, '@'))
 {
   int uh_len;
   char *b = (char*) MyMalloc((uh_len = strlen($3)+3));
   ircd_snprintf(0, b, uh_len, "*@%s", $3);
   aconf->host = b;
 }
 else
   DupString(aconf->host, $3);
};

operclass: CLASS '=' QSTRING ';'
{
 aconf->conn_class = find_class($3);
};

priv: privtype '=' yesorno ';'
{
  PrivSet(&privs_dirty, $1);
  if (($3 == 1) ^ invert)
    PrivSet(&privs, $1);
  else
    PrivClr(&privs, $1);
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
          TPRIV_LOCAL_BADCHAN { $$ = TPRIV_LOCAL_BADCHAN; } |
          TPRIV_SEE_CHAN { $$ = PRIV_SEE_CHAN; } |
          TPRIV_SHOW_INVIS { $$ = PRIV_SHOW_INVIS; } |
          TPRIV_SHOW_ALL_INVIS { $$ = PRIV_SHOW_ALL_INVIS; } |
          TPRIV_PROPAGATE { $$ = PRIV_PROPAGATE; } |
          TPRIV_UNLIMIT_QUERY { $$ = PRIV_UNLIMIT_QUERY; } |
          TPRIV_DISPLAY { $$ = PRIV_DISPLAY; } |
          TPRIV_SEE_OPERS { $$ = PRIV_SEE_OPERS; } |
          TPRIV_WIDE_GLINE { $$ = PRIV_WIDE_GLINE; } |
          LOCAL { $$ = PRIV_PROPAGATE; invert = 1; } |
          TPRIV_FORCE_OPMODE { $$ = PRIV_FORCE_OPMODE; } |
          TPRIV_FORCE_LOCAL_OPMODE { $$ = PRIV_FORCE_LOCAL_OPMODE; };

yesorno: YES { $$ = 1; } | NO { $$ = 0; };

/* The port block... */
portblock: PORT {
  port = 0;
  host = NULL;
  /* Hijack these for is_server, is_hidden to cut down on globals... */
  tconn = 0;
  tping = 0;
  /* and this for mask... */
  pass = NULL;
} '{' portitems '}' ';'
{
  if (port > 0 && port <= 0xFFFF)
  {
    add_listener(port, host, pass, tconn, tping);
  }
  else
  {
    parse_error("Bad port block");
  }
  MyFree(host);
  MyFree(pass);
  host = pass = NULL;
};
portitems: portitem portitems | portitem;
portitem: portnumber | portvhost | portmask | portserver | porthidden | error;
portnumber: PORT '=' NUMBER ';'
{
  port = $3;
};

portvhost: VHOST '=' QSTRING ';'
{
  MyFree(host);
  DupString(host, $3);
};

portmask: MASK '=' QSTRING ';'
{
  MyFree(pass);
  DupString(pass, $3);
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
  aconf = (struct ConfItem*) MyMalloc(sizeof(*aconf));
  memset(aconf, 0, sizeof(*aconf));
  aconf->status = CONF_CLIENT;
} '{' clientitems '}'
{
  if ((aconf->host != NULL || aconf->name!=NULL))
  {
    if (aconf->host == NULL)
      DupString(aconf->host, "");
    if (aconf->name == NULL)
      DupString(aconf->name, "");
    if (aconf->conn_class == NULL)
      aconf->conn_class = find_class("default");
    aconf->next = GlobalConfList;
    GlobalConfList = aconf;
    aconf = NULL;
  }
  else
  {
   MyFree(aconf->host);
   MyFree(aconf->passwd);
   MyFree(aconf);
   aconf = NULL;
   parse_error("Bad client block");
  }
} ';';
clientitems: clientitem clientitems | clientitem;
clientitem: clienthost | clientclass | clientpass | clientip | error;
clientip: IP '=' QSTRING ';'
{
  MyFree(aconf->host);
  DupString(aconf->host, $3);
};

clienthost: HOST '=' QSTRING ';'
{
  MyFree(aconf->name);
  DupString(aconf->name, $3);
};

clientclass: CLASS '=' QSTRING ';'
{
  aconf->conn_class = find_class($3);
};

clientpass: PASS '=' QSTRING ';'
{
  MyFree(aconf->passwd);
  DupString(aconf->passwd, $3);
};

killblock: KILL
{
  dconf = (struct DenyConf*) MyMalloc(sizeof(*dconf));
  memset(dconf, 0, sizeof(*dconf));
} '{' killitems '}'
{
  if (dconf->hostmask != NULL)
  {
    if (dconf->usermask == NULL)
      DupString(dconf->usermask, "*");
    dconf->next = denyConfList;
    denyConfList = dconf;
    dconf = NULL;
  }
  else
  {
    MyFree(dconf->hostmask);
    MyFree(dconf->message);
    MyFree(dconf);
    dconf = NULL;
    parse_error("Bad kill block");
  }
} ';';
killitems: killitem killitems | killitem;
killitem: killuhost | killreal | killreasonfile | killreason | error;
killuhost: HOST '=' QSTRING ';'
{
  char *u, *h;
  dconf->flags &= ~DENY_FLAGS_REALNAME;
  MyFree(dconf->hostmask);
  MyFree(dconf->usermask);
  if ((h = strchr($3, '@')) == NULL)
  {
    u = "*";
    h = $3;
  }
  else
  {
    u = $3;
    h++;
  }
  DupString(dconf->hostmask, h);
  DupString(dconf->usermask, u);
  ipmask_parse(dconf->hostmask, &dconf->address, &dconf->bits);
};

killreal: REAL '=' QSTRING ';'
{
 dconf->flags &= ~DENY_FLAGS_IP;
 dconf->flags |= DENY_FLAGS_REALNAME;
 MyFree(dconf->hostmask);
 /* Leave usermask so you can specify user and real... */
 DupString(dconf->hostmask, $3);
};

killreason: REASON '=' QSTRING ';'
{
 dconf->flags &= DENY_FLAGS_FILE;
 MyFree(dconf->message);
 DupString(dconf->message, $3);
};

killreasonfile: TFILE '=' QSTRING ';'
{
 dconf->flags |= DENY_FLAGS_FILE;
 MyFree(dconf->message);
 DupString(dconf->message, $3);
};

cruleblock: CRULE
{
  host = pass = NULL;
  tconn = CRULE_AUTO;
} '{' cruleitems '}'
{
  struct CRuleNode *node;
  if (host != NULL && pass != NULL && (node=crule_parse(pass)) != NULL)
  {
    struct CRuleConf *p = (struct CRuleConf*) MyMalloc(sizeof(*p));
    p->hostmask = host;
    p->rule = pass;
    p->type = tconn;
    p->node = node;
    p->next = cruleConfList;
    cruleConfList = p;
  }
  else
  {
    MyFree(host);
    MyFree(pass);
    parse_error("Bad CRule block");
  }
} ';';

cruleitems: cruleitem cruleitems | cruleitem;
cruleitem: cruleserver | crulerule | cruleall | error;

cruleserver: SERVER '=' QSTRING ';'
{
  MyFree(host);
  collapse($3);
  DupString(host, $3);
};

crulerule: RULE '=' QSTRING ';'
{
 MyFree(pass);
 DupString(pass, $3);
};

cruleall: ALL '=' YES ';'
{
 tconn = CRULE_ALL;
} | ALL '=' NO ';'
{
 tconn = CRULE_AUTO;
};

motdblock: MOTD {
 pass = host = NULL;
} '{' motditems '}'
{
  if (host != NULL && pass != NULL)
    motd_add(host, pass);
  MyFree(host);
  MyFree(pass);
  host = pass = NULL;
} ';';

motditems: motditem motditems | motditem;
motditem: motdhost | motdfile | error;
motdhost: HOST '=' QSTRING ';'
{
  DupString(host, $3);
};

motdfile: TFILE '=' QSTRING ';'
{
  DupString(pass, $3);
};

featuresblock: FEATURES '{' featureitems '}' ';';
featureitems: featureitems featureitem | featureitem;

featureitem: QSTRING
{
  stringlist[0] = $1;
  stringno = 1;
} '=' stringlist ';';

stringlist: QSTRING
{
  stringlist[1] = $1;
  stringno = 2;
} posextrastrings
{
  feature_set(NULL, (const char * const *)stringlist, stringno);
};
posextrastrings: /* empty */ | extrastrings;
extrastrings: extrastrings extrastring | extrastring;
extrastring: QSTRING
{
  if (stringno < MAX_STRINGS)
    stringlist[stringno++] = $1;
};

quarantineblock: QUARANTINE '{'
{
  if (qconf != NULL)
    qconf = (struct qline*) MyMalloc(sizeof(*qconf));
  else
  {
    if (qconf->chname != NULL)
      MyFree(qconf->chname);
    if (qconf->reason != NULL)
      MyFree(qconf->reason);
  }
  memset(qconf, 0, sizeof(*qconf));
} quarantineitems '}' ';'
{
  if (qconf->chname == NULL || qconf->reason == NULL)
  {
    log_write(LS_CONFIG, L_ERROR, 0, "quarantine blocks need a channel name "
              "and a reason.");
    return 0;
  }
  qconf->next = GlobalQuarantineList;
  GlobalQuarantineList = qconf;
  qconf = NULL;
};

quarantineitems: CHANNEL NAME '=' QSTRING ';'
{
  DupString(qconf->chname, $4);
} | REASON '=' QSTRING ';'
{
  DupString(qconf->reason, $3);
};

pseudoblock: PSEUDO QSTRING '{'
{
  smap = MyCalloc(1, sizeof(struct s_map));
  DupString(smap->command, $2);
}
pseudoitems '}' ';'
{
  if (!smap->name || !smap->services)
  {
    log_write(LS_CONFIG, L_ERROR, 0, "pseudo commands need a service name and list of target nicks.");
    return 0;
  }
  if (register_mapping(smap))
  {
    smap->next = GlobalServiceMapList;
    GlobalServiceMapList = smap;
  }
  else
  {
    struct nick_host *nh, *next;
    for (nh = smap->services; nh; nh = next)
    {
      next = nh->next;
      MyFree(nh);
    }
    MyFree(smap->name);
    MyFree(smap->command);
    MyFree(smap->prepend);
    MyFree(smap);
  }
  smap = NULL;
};

pseudoitems: pseudoitem pseudoitems | pseudoitem;
pseudoitem: pseudoname | pseudoprepend | pseudonick | error;
pseudoname: NAME '=' QSTRING ';'
{
  DupString(smap->name, $3);
};
pseudoprepend: PREPEND '=' QSTRING ';'
{
  DupString(smap->prepend, $3);
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
};

iauthblock: IAUTH '{'
{
  pass = host = NULL;
  port = 0;
  tconn = 60;
  tping = 60;
} iauthitems '}' ';'
{
  if (!host || !port) {
    log_write(LS_CONFIG, L_ERROR, 0, "IAuth block needs a server name and port.");
    return 0;
  }
  iauth_connect(host, port, pass, tconn, tping);
  MyFree(pass);
  MyFree(host);
  pass = host = NULL;
};

iauthitems: iauthitem iauthitems | iauthitem;
iauthitem: iauthpass | iauthhost | iauthport | iauthconnfreq | iauthtimeout | error;
iauthpass: PASS '=' QSTRING ';'
{
  MyFree(pass);
  DupString(pass, $3);
};
iauthhost: HOST '=' QSTRING ';'
{
  MyFree(host);
  DupString(host, $3);
};
iauthport: PORT '=' NUMBER ';'
{
  port = $3;
};
iauthconnfreq: CONNECTFREQ '=' timespec ';'
{
  tconn = $3;
};
iauthtimeout: TIMEOUT '=' timespec ';'
{
  tping = $3;
};
