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
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "support.h"
#include "sys.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#define MAX_STRINGS 80 /* Maximum number of feature params. */
  extern struct LocalConf   localConf;
  extern struct DenyConf*   denyConfList;
  extern struct CRuleConf*  cruleConfList;
  extern struct ServerConf* serverConfList;

  int yylex(void);
  /* Now all the globals we need :/... */
  int tping, tconn, maxlinks, sendq, port;
  int stringno;
  char *name, *pass, *host;
  char *stringlist[MAX_STRINGS];
  struct ConnectionClass *class;
  struct ConfItem *aconf;
  struct DenyConf *dconf;
  struct ServerConf *sconf;
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
%token PORT
%token VHOST
%token MASK
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
/* and now a lot of priviledges... */
%token TPRIV_CHAN_LIMIT, TPRIV_MODE_LCHAN, TPRIV_DEOP_LCHAN, TPRIV_WALK_LCHAN
%token TPRIV_KILL, TPRIV_LOCAL_KILL, TPRIV_REHASH, TPRIV_RESTART, TPRIV_DIE
%token TPRIV_GLINE, TPRIV_LOCAL_GLINE, TPRIV_JUPE, TPRIV_LOCAL_JUPE
%token TPRIV_LOCAL_OPMODE, TPRIV_OPMODE, TPRIV_SET, TPRIV_WHOX, TPRIV_BADCHAN
%token TPRIV_LOCAL_BADCHAN
%token TPRIV_SEE_CHAN, TPRIV_SHOW_INVIS, TPRIV_SHOW_ALL_INVIS, TPRIV_PROPAGATE
%token TPRIV_UNLIMIT_QUERY, TPRIV_DISPLAY, TPRIV_SEE_OPERS, TPRIV_WIDE_GLINE
/* and some types... */
%type <num> sizespec
%type <num> timespec, timefactor, factoredtimes, factoredtime
%type <num> expr, yesorno, privtype
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
       killblock | cruleblock | motdblock | featuresblock;

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


sizespec:	expr	
		= {
			$$ = $1;
		}
		| expr BYTES
		= { 
			$$ = $1;
		}
		| expr KBYTES
		= {
			$$ = $1 * 1024;
		}
		| expr MBYTES
		= {
			$$ = $1 * 1024 * 1024;
		}
		| expr GBYTES
		= {
			$$ = $1 * 1024 * 1024 * 1024;
		}
		| expr TBYTES
		= {
			$$ = $1 * 1024 * 1024 * 1024;
		}
		;

/* this is an arithmatic expression */
expr: NUMBER
		= { 
			$$ = $1;
		}
		| expr '+' expr
		= { 
			$$ = $1 + $3;
		}
		| expr '-' expr
		= { 
			$$ = $1 - $3;
		}
		| expr '*' expr
		= { 
			$$ = $1 * $3;
		}
		| expr '/' expr
		= { 
			$$ = $1 / $3;
		}
/* leave this out until we find why it makes BSD yacc dump core -larne
		| '-' expr  %prec NEG
		= {
			$$ = -$2;
		} */
		| '(' expr ')'
		= {
			$$ = $2;
		}
		;

jupeblock: JUPE '{' jupeitems '}' ';' ;
jupeitems: jupeitem jupeitems | jupeitem;
jupeitem: jupenick;
jupenick: NICK '=' QSTRING
{
  addNickJupes(yylval.text);
} ';';

generalblock: GENERAL '{' generalitems '}' ';' ;
generalitems: generalitem generalitems | generalitem;
generalitem: generalnumeric | generalname | generalvhost | generaldesc;
generalnumeric: NUMERIC '=' NUMBER ';'
{
  if (localConf.numeric == 0)
    localConf.numeric = yylval.num;
};

generalname: NAME '=' QSTRING ';'
{
  if (localConf.name == NULL)
    DupString(localConf.name, yylval.text);
};

generaldesc: DESCRIPTION '=' QSTRING ';'
{
  MyFree(localConf.description);
  DupString(localConf.description, yylval.text);
  ircd_strncpy(cli_info(&me), yylval.text, REALLEN);
};

generalvhost: VHOST '=' QSTRING ';'
{
  if (INADDR_NONE ==
      (localConf.vhost_address.s_addr = inet_addr(yylval.text)))
    localConf.vhost_address.s_addr = INADDR_ANY;
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
adminitem: adminlocation | admincontact;
adminlocation: LOCATION '=' QSTRING ';'
{
 if (localConf.location1 == NULL)
  DupString(localConf.location1, yylval.text);
 else if (localConf.location2 == NULL)
  DupString(localConf.location2, yylval.text);
 /* Otherwise just drop it. -A1kmm */
};
admincontact: CONTACT '=' QSTRING ';'
{
 if (localConf.contact != NULL)
  free(localConf.contact);
 DupString(localConf.contact, yylval.text);
};

classblock: CLASS {
 name = NULL;
 tping = 90;
 tconn = 0;
 maxlinks = 0;
 sendq = 0;
} '{' classitems '}'
{
 if (name != NULL)
 {
  add_class(name, tping, tconn, maxlinks, sendq);
 }
} ';';
classitems: classitem classitems | classitem;
classitem: classname | classpingfreq | classconnfreq | classmaxlinks |
           classsendq;
classname: NAME '=' QSTRING ';'
{
 MyFree(name);
 DupString(name, yylval.text);
};
classpingfreq: PINGFREQ '=' timespec ';'
{
 tping = yylval.num;
};
classconnfreq: CONNECTFREQ '=' timespec ';'
{
 tconn = yylval.num;
};
classmaxlinks: MAXLINKS '=' expr ';'
{
 maxlinks = yylval.num;
};
classsendq: SENDQ '=' sizespec ';'
{
 sendq = yylval.num;
};

connectblock: CONNECT
{
 name = pass = host = NULL;
 class = NULL;
 port = 0;
} '{' connectitems '}'
{
 if (name != NULL && pass != NULL && host != NULL && class != NULL && 
     /*ccount < MAXCONFLINKS &&*/ !strchr(host, '*') &&
     !strchr(host, '?'))
 {
  aconf = MyMalloc(sizeof(*aconf));
  aconf->status = CONF_SERVER;
  aconf->name = name;
  aconf->passwd = pass;
  aconf->conn_class = class;
  aconf->port = port;
  aconf->status = CONF_SERVER;
  aconf->host = host;
  aconf->next = GlobalConfList;
  aconf->ipnum.s_addr = INADDR_NONE;
  lookup_confhost(aconf);
  GlobalConfList = aconf;
  printf("Server added: %s\n", name);
  /* ccount++; -- XXX fixme --- A1kmm */
 }
 else
 {
  MyFree(name);
  MyFree(pass);
  MyFree(host);
  name = pass = host = NULL;
 }
}';';
connectitems: connectitem connectitems | connectitem;
connectitem: connectname | connectpass | connectclass | connecthost
              | connectport;
connectname: NAME '=' QSTRING ';'
{
 MyFree(name);
 DupString(name, yylval.text);
};
connectpass: PASS '=' QSTRING ';'
{
 MyFree(pass);
 DupString(pass, yylval.text);
};
connectclass: CLASS '=' QSTRING ';'
{
 class = find_class(yylval.text);
};
connecthost: HOST '=' QSTRING ';'
{
 MyFree(host);
 DupString(host, yylval.text);
};
connectport: PORT '=' NUMBER ';'
{
 port = yylval.num;
};

serverblock: SERVER
{
 aconf = MyMalloc(sizeof(*aconf));
 memset(aconf, 0, sizeof(*aconf));
} '{' serveritems '}'
{
 if (aconf->status == 0)
 {
   MyFree(aconf->host);
   MyFree(aconf->name);
   MyFree(aconf);
   aconf = NULL;
 }
 else
 {
   aconf->next = GlobalConfList;
   GlobalConfList = aconf;
 }
} ';';
serveritems: serveritem serveritems | serveritem;
serveritem: servername | servermask | serverhub | serverleaf |
             serveruworld;
servername: NAME '=' QSTRING
{
 MyFree(aconf->name);
 DupString(aconf->name, yylval.text);
} ';' ;
servermask: MASK '=' QSTRING
{
 MyFree(aconf->host);
 DupString(aconf->host, yylval.text);
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
  aconf = MyMalloc(sizeof(*aconf));
  memset(aconf, 0, sizeof(*aconf));
  aconf->status = CONF_OPERATOR;
  set_initial_oper_privs(aconf, (FLAGS_OPER | FLAGS_LOCOP));
} '{' operitems '}' ';'
{
  if (aconf->name != NULL && aconf->passwd != NULL && aconf->host != NULL)
  {
    log_write(LS_CONFIG, L_ERROR, 0, "added an oper block for host %s", aconf->host);
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
operitem: opername | operpass | operlocal | operhost | operclass | operpriv;

opername: NAME '=' QSTRING ';'
{
  MyFree(aconf->name);
  DupString(aconf->name, yylval.text);
};

operpass: PASS '=' QSTRING ';'
{
  MyFree(aconf->passwd);
  DupString(aconf->passwd, yylval.text);
};

operlocal: LOCAL '=' YES ';'
{
  /* XXX it would be good to get rid of local operators and add same
   * permission values here. But for now, I am just going with local 
   * opers... */
  aconf->status = CONF_LOCOP;
  /* XXX blow away existing priviledges. */
  set_initial_oper_privs(aconf, FLAGS_LOCOP);
} | LOCAL '=' NO ';'
{
  /* XXX blow away existing priviledges. */
  set_initial_oper_privs(aconf, (FLAGS_OPER|FLAGS_LOCOP));
  aconf->status = CONF_OPERATOR;
};

operhost: HOST '=' QSTRING ';'
{
 MyFree(aconf->host);
 if (!strchr(yylval.text, '@'))
 {
   int uh_len;
   char *b = MyMalloc((uh_len = strlen(yylval.text)+3));
   ircd_snprintf(0, b, uh_len, "*@%s", yylval.text);
   aconf->host = b;
 }
 else
   DupString(aconf->host, yylval.text);
};

operclass: CLASS '=' QSTRING ';'
{
 aconf->conn_class = find_class(yylval.text);
};

operpriv: privtype '=' yesorno ';'
{
  if ($3 == 1)
    PrivSet(&aconf->privs, $1);
  else
    PrivClr(&aconf->privs, $1);
};

privtype: TPRIV_CHAN_LIMIT { $$ = PRIV_CHAN_LIMIT; } |
          TPRIV_MODE_LCHAN { $$ = PRIV_MODE_LCHAN; } |
          TPRIV_DEOP_LCHAN { $$ = PRIV_DEOP_LCHAN; } |
          TPRIV_WALK_LCHAN { $$ = PRIV_WALK_LCHAN; } |
          TPRIV_KILL { $$ = PRIV_KILL; } |
          TPRIV_LOCAL_KILL { $$ = PRIV_LOCAL_KILL; } |
          TPRIV_REHASH { $$ = PRIV_REHASH; } |
          TPRIV_RESTART { $$ = PRIV_RESTART; } |
          TPRIV_DIE { $$ = PRIV_DIE; } |
          TPRIV_GLINE { $$ = PRIV_GLINE; } |
          TPRIV_LOCAL_GLINE { $$ = PRIV_LOCAL_GLINE; } |
          TPRIV_JUPE { $$ = PRIV_JUPE; } |
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
          TPRIV_WIDE_GLINE { $$ = PRIV_WIDE_GLINE; };

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
    host = pass = NULL;
  }
  else
  {
    MyFree(host);
    MyFree(pass);
  }
};
portitems: portitem portitems | portitem;
portitem: portnumber | portvhost | portmask | portserver | porthidden;
portnumber: PORT '=' NUMBER ';'
{
  port = yylval.num;
};

portvhost: VHOST '=' QSTRING ';'
{
  MyFree(host);
  DupString(host, yylval.text);
};

portmask: MASK '=' QSTRING ';'
{
  MyFree(pass);
  DupString(pass, yylval.text);
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
  aconf = MyMalloc(sizeof(*aconf));
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
  }
} ';';
clientitems: clientitem clientitems | clientitem;
clientitem: clienthost | clientclass | clientpass | clientip;
clientip: IP '=' QSTRING ';'
{
  MyFree(aconf->host);
  DupString(aconf->host, yylval.text);
};

clienthost: HOST '=' QSTRING ';'
{
  MyFree(aconf->name);
  DupString(aconf->name, yylval.text);
};

clientclass: CLASS '=' QSTRING ';'
{
  aconf->conn_class = find_class(yylval.text);
};

clientpass: PASS '=' QSTRING ';'
{
  MyFree(aconf->passwd);
  DupString(aconf->passwd, yylval.text);
};

killblock: KILL
{
  dconf = MyMalloc(sizeof(*dconf));
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
  }
} ';';
killitems: killitem killitems | killitem;
killitem: killuhost | killreal | killreasonfile | killreason;
killuhost: HOST '=' QSTRING ';'
{
  char *u, *h;
  dconf->flags &= ~DENY_FLAGS_REALNAME;
  MyFree(dconf->hostmask);
  MyFree(dconf->usermask);
  if ((h = strchr(yylval.text, '@')) == NULL)
  {
    u = "*";
    h = yylval.text;
  }
  else
  {
    u = yylval.text;
    h++;
  }
  DupString(dconf->hostmask, h);
  DupString(dconf->usermask, u);
  if (strchr(yylval.text, '.'))
  {
    int  c_class;
    char ipname[16];
    int  ad[4] = { 0 };
    int  bits2 = 0;
    dconf->flags |= DENY_FLAGS_IP;
    c_class = sscanf(dconf->hostmask, "%d.%d.%d.%d/%d",
                     &ad[0], &ad[1], &ad[2], &ad[3], &bits2);
    if (c_class != 5) {
      dconf->bits = c_class * 8;
    }
    else {
      dconf->bits = bits2;
    }
    ircd_snprintf(0, ipname, sizeof(ipname), "%d.%d.%d.%d", ad[0], ad[1],
		  ad[2], ad[3]);
    dconf->address = inet_addr(ipname);
  }
};

killreal: REAL '=' QSTRING ';'
{
 dconf->flags &= ~DENY_FLAGS_IP;
 dconf->flags |= DENY_FLAGS_REALNAME;
 MyFree(dconf->hostmask);
 /* Leave usermask so you can specify user and real... */
 DupString(dconf->hostmask, yylval.text);
};

killreason: REASON '=' QSTRING ';'
{
 dconf->flags &= DENY_FLAGS_FILE;
 MyFree(dconf->message);
 DupString(dconf->message, yylval.text);
};

killreasonfile: TFILE '=' QSTRING ';'
{
 dconf->flags |= DENY_FLAGS_FILE;
 MyFree(dconf->message);
 DupString(dconf->message, yylval.text);
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
    struct CRuleConf *p = MyMalloc(sizeof(*p));
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
  }
} ';';

cruleitems: cruleitem cruleitems | cruleitem;
cruleitem: cruleserver | crulerule | cruleall;

cruleserver: SERVER '=' QSTRING ';'
{
  MyFree(host);
  collapse(yylval.text);
  DupString(host, yylval.text);
};

crulerule: RULE '=' QSTRING ';'
{
 MyFree(pass);
 DupString(pass, yylval.text);
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
motditem: motdhost | motdfile;
motdhost: HOST '=' QSTRING ';'
{
  DupString(host, yylval.text);
};

motdfile: TFILE '=' QSTRING ';'
{
  DupString(pass, yylval.text);
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
