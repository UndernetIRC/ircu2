/*
 * IRC - Internet Relay Chat, include/msg.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id$
 */
#ifndef INCLUDED_msg_h
#define INCLUDED_msg_h
#ifndef INCLUDED_ircd_handler_h
#include "ircd_handler.h"
#endif

struct Client;

/*
 * General defines
 */

#define MAXPARA    15

/*-----------------------------------------------------------------------------
 * Macros
 */

/*
 * Tokenization:
 * Each command must have a TOK_COMMAND and MSG_COMMAND definition.
 * If you don't want one or the other, make them the same.
 * Also each command has a "msgclass" used for debugging purposes.
 */

/* *INDENT-OFF* */

#define MSG_PRIVATE             "PRIVMSG"       /* PRIV */
#define TOK_PRIVATE             "P"
#define CMD_PRIVATE		MSG_PRIVATE, TOK_PRIVATE

#define MSG_WHO                 "WHO"           /* WHO  -> WHOC */
#define TOK_WHO                 "H"
#define CMD_WHO			MSG_WHO, TOK_WHO

#define MSG_WHOIS               "WHOIS"         /* WHOI */
#define TOK_WHOIS               "W"
#define CMD_WHOIS		MSG_WHOIS, TOK_WHOIS

#define MSG_WHOWAS              "WHOWAS"        /* WHOW */
#define TOK_WHOWAS              "X"
#define CMD_WHOWAS		MSG_WHOWAS, TOK_WHOWAS

#define MSG_USER                "USER"          /* USER */
#define TOK_USER                "USER"
#define CMD_USER		MSG_USER, TOK_USER

#define MSG_NICK                "NICK"          /* NICK */
#define TOK_NICK                "N"
#define CMD_NICK		MSG_NICK, TOK_NICK

#define MSG_SERVER              "SERVER"        /* SERV */
#define TOK_SERVER              "S"
#define CMD_SERVER		MSG_SERVER, TOK_SERVER

#define MSG_LIST                "LIST"          /* LIST */
#define TOK_LIST                "LIST"
#define CMD_LIST		MSG_LIST, TOK_LIST

#define MSG_TOPIC               "TOPIC"         /* TOPI */
#define TOK_TOPIC               "T"
#define CMD_TOPIC		MSG_TOPIC, TOK_TOPIC

#define MSG_INVITE              "INVITE"        /* INVI */
#define TOK_INVITE              "I"
#define CMD_INVITE		MSG_INVITE, TOK_INVITE

#define MSG_VERSION             "VERSION"       /* VERS */
#define TOK_VERSION             "V"
#define CMD_VERSION		MSG_VERSION, TOK_VERSION

#define MSG_QUIT                "QUIT"          /* QUIT */
#define TOK_QUIT                "Q"
#define CMD_QUIT		MSG_QUIT, TOK_QUIT

#define MSG_SQUIT               "SQUIT"         /* SQUI */
#define TOK_SQUIT               "SQ"
#define CMD_SQUIT		MSG_SQUIT, TOK_SQUIT

#define MSG_KILL                "KILL"          /* KILL */
#define TOK_KILL                "D"
#define CMD_KILL		MSG_KILL, TOK_KILL

#define MSG_INFO                "INFO"          /* INFO */
#define TOK_INFO                "F"
#define CMD_INFO		MSG_INFO, TOK_INFO

#define MSG_LINKS               "LINKS"         /* LINK */
#define TOK_LINKS               "LI"
#define CMD_LINKS		MSG_LINKS, TOK_LINKS

#define MSG_STATS               "STATS"         /* STAT */
#define TOK_STATS               "R"
#define CMD_STATS		MSG_STATS, TOK_STATS

#define MSG_HELP                "HELP"          /* HELP */
#define TOK_HELP                "HELP"
#define CMD_HELP		MSG_HELP, TOK_HELP

#define MSG_ERROR               "ERROR"         /* ERRO */
#define TOK_ERROR               "Y"
#define CMD_ERROR		MSG_ERROR, TOK_ERROR

#define MSG_AWAY                "AWAY"          /* AWAY */
#define TOK_AWAY                "A"
#define CMD_AWAY		MSG_AWAY, TOK_AWAY

#define MSG_CONNECT             "CONNECT"       /* CONN */
#define TOK_CONNECT             "CO"
#define CMD_CONNECT		MSG_CONNECT, TOK_CONNECT

#define MSG_MAP                 "MAP"           /* MAP  */
#define TOK_MAP                 "MAP"
#define CMD_MAP			MSG_MAP, TOK_MAP

#define MSG_PING                "PING"          /* PING */
#define TOK_PING                "G"
#define CMD_PING		MSG_PING, TOK_PING

#define MSG_PONG                "PONG"          /* PONG */
#define TOK_PONG                "Z"
#define CMD_PONG		MSG_PONG, TOK_PONG

#define MSG_OPER                "OPER"          /* OPER */
#define TOK_OPER                "OPER"
#define CMD_OPER		MSG_OPER, TOK_OPER

#define MSG_PASS                "PASS"          /* PASS */
#define TOK_PASS                "PA"
#define CMD_PASS		MSG_PASS, TOK_PASS

#define MSG_WALLOPS             "WALLOPS"       /* WALL */
#define TOK_WALLOPS             "WA"
#define CMD_WALLOPS		MSG_WALLOPS, TOK_WALLOPS

#define MSG_WALLUSERS           "WALLUSERS"     /* WALL */
#define TOK_WALLUSERS           "WU"
#define CMD_WALLUSERS		MSG_WALLUSERS, TOK_WALLUSERS

#define MSG_DESYNCH             "DESYNCH"       /* DESY */
#define TOK_DESYNCH             "DS"
#define CMD_DESYNCH		MSG_DESYNCH, TOK_DESYNCH

#define MSG_TIME                "TIME"          /* TIME */
#define TOK_TIME                "TI"
#define CMD_TIME		MSG_TIME, TOK_TIME

#define MSG_SETTIME             "SETTIME"       /* SETT */
#define TOK_SETTIME             "SE"
#define CMD_SETTIME		MSG_SETTIME, TOK_SETTIME

#define MSG_RPING               "RPING"         /* RPIN */
#define TOK_RPING               "RI"
#define CMD_RPING		MSG_RPING, TOK_RPING

#define MSG_RPONG               "RPONG"         /* RPON */
#define TOK_RPONG               "RO"
#define CMD_RPONG		MSG_RPONG, TOK_RPONG

#define MSG_NAMES               "NAMES"         /* NAME */
#define TOK_NAMES               "E"
#define CMD_NAMES		MSG_NAMES, TOK_NAMES

#define MSG_ADMIN               "ADMIN"         /* ADMI */
#define TOK_ADMIN               "AD"
#define CMD_ADMIN		MSG_ADMIN, TOK_ADMIN

#define MSG_TRACE               "TRACE"         /* TRAC */
#define TOK_TRACE               "TR"
#define CMD_TRACE		MSG_TRACE, TOK_TRACE

#define MSG_NOTICE              "NOTICE"        /* NOTI */
#define TOK_NOTICE              "O"
#define CMD_NOTICE		MSG_NOTICE, TOK_NOTICE

#define MSG_WALLCHOPS           "WALLCHOPS"     /* WC */
#define TOK_WALLCHOPS           "WC"
#define CMD_WALLCHOPS		MSG_WALLCHOPS, TOK_WALLCHOPS

#define MSG_WALLVOICES           "WALLVOICES"     /* WV */
#define TOK_WALLVOICES           "WV"
#define CMD_WALLVOICES           MSG_WALLVOICES, TOK_WALLVOICES

#define MSG_CPRIVMSG            "CPRIVMSG"      /* CPRI */
#define TOK_CPRIVMSG            "CP"
#define CMD_CPRIVMSG		MSG_CPRIVMSG, TOK_CPRIVMSG

#define MSG_CNOTICE             "CNOTICE"       /* CNOT */
#define TOK_CNOTICE             "CN"
#define CMD_CNOTICE		MSG_CNOTICE, TOK_CNOTICE

#define MSG_JOIN                "JOIN"          /* JOIN */
#define TOK_JOIN                "J"
#define CMD_JOIN		MSG_JOIN, TOK_JOIN

#define MSG_PART                "PART"          /* PART */
#define TOK_PART                "L"
#define CMD_PART		MSG_PART, TOK_PART

#define MSG_LUSERS              "LUSERS"        /* LUSE */
#define TOK_LUSERS              "LU"
#define CMD_LUSERS		MSG_LUSERS, TOK_LUSERS

#define MSG_MOTD                "MOTD"          /* MOTD */
#define TOK_MOTD                "MO"
#define CMD_MOTD		MSG_MOTD, TOK_MOTD

#define MSG_MODE                "MODE"          /* MODE */
#define TOK_MODE                "M"
#define CMD_MODE		MSG_MODE, TOK_MODE

#define MSG_KICK                "KICK"          /* KICK */
#define TOK_KICK                "K"
#define CMD_KICK		MSG_KICK, TOK_KICK

#define MSG_USERHOST            "USERHOST"      /* USER -> USRH */
#define TOK_USERHOST            "USERHOST"
#define CMD_USERHOST		MSG_USERHOST, TOK_USERHOST

#define MSG_USERIP              "USERIP"        /* USER -> USIP */
#define TOK_USERIP              "USERIP"
#define CMD_USERIP		MSG_USERIP, TOK_USERIP

#define MSG_ISON                "ISON"          /* ISON */
#define TOK_ISON                "ISON"
#define CMD_ISON		MSG_ISON, TOK_ISON

#define MSG_SQUERY              "SQUERY"        /* SQUE */
#define TOK_SQUERY              "SQUERY"
#define CMD_SQUERY		MSG_SQUERY, TOK_SQUERY

#define MSG_SERVLIST            "SERVLIST"      /* SERV -> SLIS */
#define TOK_SERVLIST            "SERVSET"
#define CMD_SERVLIST		MSG_SERVLIST, TOK_SERVLIST

#define MSG_SERVSET             "SERVSET"       /* SERV -> SSET */
#define TOK_SERVSET             "SERVSET"
#define CMD_SERVSET		MSG_SERVSET, TOK_SERVSET

#define MSG_REHASH              "REHASH"        /* REHA */
#define TOK_REHASH              "REHASH"
#define CMD_REHASH		MSG_REHASH, TOK_REHASH

#define MSG_RESTART             "RESTART"       /* REST */
#define TOK_RESTART             "RESTART"
#define CMD_RESTART		MSG_RESTART, TOK_RESTART

#define MSG_CLOSE               "CLOSE"         /* CLOS */
#define TOK_CLOSE               "CLOSE"
#define CMD_CLOSE		MSG_CLOSE, TOK_CLOSE

#define MSG_DIE                 "DIE"           /* DIE  */
#define TOK_DIE                 "DIE"
#define CMD_DIE			MSG_DIE, TOK_DIE

#define MSG_HASH                "HASH"          /* HASH */
#define TOK_HASH                "HASH"
#define CMD_HASH		MSG_HASH, TOK_HASH

#define MSG_DNS                 "DNS"           /* DNS  -> DNSS */
#define TOK_DNS                 "DNS"
#define CMD_DNS			MSG_DNS, TOK_DNS

#define MSG_SILENCE             "SILENCE"       /* SILE */
#define TOK_SILENCE             "U"
#define CMD_SILENCE		MSG_SILENCE, TOK_SILENCE

#define MSG_GLINE               "GLINE"         /* GLIN */
#define TOK_GLINE               "GL"
#define CMD_GLINE		MSG_GLINE, TOK_GLINE

#define MSG_BURST               "BURST"         /* BURS */
#define TOK_BURST               "B"
#define CMD_BURST		MSG_BURST, TOK_BURST

#define MSG_UPING               "UPING"         /* UPIN */
#define TOK_UPING               "UP"
#define CMD_UPING		MSG_UPING, TOK_UPING

#define MSG_CREATE              "CREATE"        /* CREA */
#define TOK_CREATE              "C"
#define CMD_CREATE		MSG_CREATE, TOK_CREATE

#define MSG_DESTRUCT            "DESTRUCT"      /* DEST */
#define TOK_DESTRUCT            "DE"
#define CMD_DESTRUCT		MSG_DESTRUCT, TOK_DESTRUCT

#define MSG_END_OF_BURST        "END_OF_BURST"  /* END_ */
#define TOK_END_OF_BURST        "EB"
#define CMD_END_OF_BURST	MSG_END_OF_BURST, TOK_END_OF_BURST

#define MSG_END_OF_BURST_ACK    "EOB_ACK"       /* EOB_ */
#define TOK_END_OF_BURST_ACK    "EA"
#define CMD_END_OF_BURST_ACK	MSG_END_OF_BURST_ACK, TOK_END_OF_BURST_ACK

#define MSG_PROTO               "PROTO"         /* PROTO */
#define TOK_PROTO               "PROTO"         /* PROTO */
#define CMD_PROTO		MSG_PROTO, TOK_PROTO

#define MSG_JUPE                "JUPE"          /* JUPE */
#define TOK_JUPE                "JU"
#define CMD_JUPE		MSG_JUPE, TOK_JUPE

#define MSG_OPMODE              "OPMODE"        /* OPMO */
#define TOK_OPMODE              "OM"
#define CMD_OPMODE		MSG_OPMODE, TOK_OPMODE

#define MSG_CLEARMODE           "CLEARMODE"     /* CLMO */
#define TOK_CLEARMODE           "CM"
#define CMD_CLEARMODE		MSG_CLEARMODE, TOK_CLEARMODE

#define MSG_ACCOUNT		"ACCOUNT"	/* ACCO */
#define TOK_ACCOUNT		"AC"
#define CMD_ACCOUNT		MSG_ACCOUNT, TOK_ACCOUNT

#define MSG_ASLL		"ASLL"		/* ASLL */
#define TOK_ASLL		"LL"
#define CMD_ASLL		MSG_ASLL, TOK_ASLL

#define MSG_POST                "POST"          /* POST */
#define TOK_POST                "POST"

#define MSG_SET			"SET"		/* SET */
#define TOK_SET			"SET"

#define MSG_RESET		"RESET"		/* RESE */
#define TOK_RESET		"RESET"

#define MSG_GET			"GET"		/* GET */
#define TOK_GET			"GET"

#define MSG_PRIVS		"PRIVS"		/* PRIV */
#define TOK_PRIVS		"PRIVS"

/*
 * Constants
 */
#define   MFLG_SLOW              0x01   /* Command can be executed roughly    *
                                         * once per 2 seconds.                */
#define   MFLG_UNREG             0x02   /* Command available to unregistered  *
                                         * clients.                           */
#define   MFLG_IGNORE            0x04   /* silently ignore command from
                                         * unregistered clients */

/*
 * Structures
 */
struct Message {
  char *cmd;                  /* command string */
  char *tok;                  /* token (shorter command string) */
  unsigned int count;         /* number of times message used */
  unsigned int parameters;
  unsigned int flags;           /* bit 0 set means that this command is allowed
                                   to be used only on the average of once per 2
                                   seconds -SRB */
  unsigned int bytes;         /* bytes received for this message */
  /*
   * cptr = Connected client ptr
   * sptr = Source client ptr
   * parc = parameter count
   * parv = parameter variable array
   */
  /* handlers:
   * UNREGISTERED, CLIENT, SERVER, OPER, SERVICE, LAST
   */
  MessageHandler handlers[LAST_HANDLER_TYPE];
};

extern struct Message msgtab[];

#endif /* INCLUDED_msg_h */
