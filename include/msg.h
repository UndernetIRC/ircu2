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

#define MSG_WHO                 "WHO"           /* WHO  -> WHOC */
#define TOK_WHO                 "H"

#define MSG_WHOIS               "WHOIS"         /* WHOI */
#define TOK_WHOIS               "W"

#define MSG_WHOWAS              "WHOWAS"        /* WHOW */
#define TOK_WHOWAS              "X"

#define MSG_USER                "USER"          /* USER */
#define TOK_USER                "USER"

#define MSG_NICK                "NICK"          /* NICK */
#define TOK_NICK                "N"

#define MSG_SERVER              "SERVER"        /* SERV */
#define TOK_SERVER              "S"

#define MSG_LIST                "LIST"          /* LIST */
#define TOK_LIST                "LIST"

#define MSG_TOPIC               "TOPIC"         /* TOPI */
#define TOK_TOPIC               "T"

#define MSG_INVITE              "INVITE"        /* INVI */
#define TOK_INVITE              "I"

#define MSG_VERSION             "VERSION"       /* VERS */
#define TOK_VERSION             "V"

#define MSG_QUIT                "QUIT"          /* QUIT */
#define TOK_QUIT                "Q"

#define MSG_SQUIT               "SQUIT"         /* SQUI */
#define TOK_SQUIT               "SQ"

#define MSG_KILL                "KILL"          /* KILL */
#define TOK_KILL                "D"

#define MSG_INFO                "INFO"          /* INFO */
#define TOK_INFO                "F"

#define MSG_LINKS               "LINKS"         /* LINK */
#define TOK_LINKS               "LI"

#define MSG_STATS               "STATS"         /* STAT */
#define TOK_STATS               "R"

#define MSG_HELP                "HELP"          /* HELP */
#define TOK_HELP                "HELP"

#define MSG_ERROR               "ERROR"         /* ERRO */
#define TOK_ERROR               "Y"

#define MSG_AWAY                "AWAY"          /* AWAY */
#define TOK_AWAY                "A"

#define MSG_CONNECT             "CONNECT"       /* CONN */
#define TOK_CONNECT             "CO"

#define MSG_MAP                 "MAP"           /* MAP  */
#define TOK_MAP                 "MAP"

#define MSG_PING                "PING"          /* PING */
#define TOK_PING                "G"

#define MSG_PONG                "PONG"          /* PONG */
#define TOK_PONG                "Z"

#define MSG_OPER                "OPER"          /* OPER */
#define TOK_OPER                "OPER"

#define MSG_PASS                "PASS"          /* PASS */
#define TOK_PASS                "PA"

#define MSG_WALLOPS             "WALLOPS"       /* WALL */
#define TOK_WALLOPS             "WA"

#define MSG_DESYNCH             "DESYNCH"       /* DESY */
#define TOK_DESYNCH             "DS"

#define MSG_TIME                "TIME"          /* TIME */
#define TOK_TIME                "TI"

#define MSG_SETTIME             "SETTIME"       /* SETT */
#define TOK_SETTIME             "SE"

#define MSG_RPING               "RPING"         /* RPIN */
#define TOK_RPING               "RI"

#define MSG_RPONG               "RPONG"         /* RPON */
#define TOK_RPONG               "RO"

#define MSG_NAMES               "NAMES"         /* NAME */
#define TOK_NAMES               "E"

#define MSG_ADMIN               "ADMIN"         /* ADMI */
#define TOK_ADMIN               "AD"

#define MSG_TRACE               "TRACE"         /* TRAC */
#define TOK_TRACE               "TR"

#define MSG_NOTICE              "NOTICE"        /* NOTI */
#define TOK_NOTICE              "O"

#define MSG_WALLCHOPS           "WALLCHOPS"     /* WC */
#define TOK_WALLCHOPS           "WC"

#define MSG_CPRIVMSG            "CPRIVMSG"      /* CPRI */
#define TOK_CPRIVMSG            "CP"

#define MSG_CNOTICE             "CNOTICE"       /* CNOT */
#define TOK_CNOTICE             "CN"

#define MSG_JOIN                "JOIN"          /* JOIN */
#define TOK_JOIN                "J"

#define MSG_PART                "PART"          /* PART */
#define TOK_PART                "L"

#define MSG_LUSERS              "LUSERS"        /* LUSE */
#define TOK_LUSERS              "LU"

#define MSG_MOTD                "MOTD"          /* MOTD */
#define TOK_MOTD                "MO"

#define MSG_MODE                "MODE"          /* MODE */
#define TOK_MODE                "M"

#define MSG_KICK                "KICK"          /* KICK */
#define TOK_KICK                "K"

#define MSG_USERHOST            "USERHOST"      /* USER -> USRH */
#define TOK_USERHOST            "USERHOST"

#define MSG_USERIP              "USERIP"        /* USER -> USIP */
#define TOK_USERIP              "USERIP"

#define MSG_ISON                "ISON"          /* ISON */
#define TOK_ISON                "ISON"

#define MSG_SQUERY              "SQUERY"        /* SQUE */
#define TOK_SQUERY              "SQUERY"

#define MSG_SERVLIST            "SERVLIST"      /* SERV -> SLIS */
#define TOK_SERVLIST            "SERVSET"

#define MSG_SERVSET             "SERVSET"       /* SERV -> SSET */
#define TOK_SERVSET             "SERVSET"

#define MSG_REHASH              "REHASH"        /* REHA */
#define TOK_REHASH              "REHASH"

#define MSG_RESTART             "RESTART"       /* REST */
#define TOK_RESTART             "RESTART"

#define MSG_CLOSE               "CLOSE"         /* CLOS */
#define TOK_CLOSE               "CLOSE"

#define MSG_DIE                 "DIE"           /* DIE  */
#define TOK_DIE                 "DIE"

#define MSG_HASH                "HASH"          /* HASH */
#define TOK_HASH                "HASH"

#define MSG_DNS                 "DNS"           /* DNS  -> DNSS */
#define TOK_DNS                 "DNS"

#define MSG_SILENCE             "SILENCE"       /* SILE */
#define TOK_SILENCE             "U"

#define MSG_GLINE               "GLINE"         /* GLIN */
#define TOK_GLINE               "GL"

#define MSG_BURST               "BURST"         /* BURS */
#define TOK_BURST               "B"

#define MSG_UPING               "UPING"         /* UPIN */
#define TOK_UPING               "UP"

#define MSG_CREATE              "CREATE"        /* CREA */
#define TOK_CREATE              "C"

#define MSG_DESTRUCT            "DESTRUCT"      /* DEST */
#define TOK_DESTRUCT            "DE"

#define MSG_END_OF_BURST        "END_OF_BURST"  /* END_ */
#define TOK_END_OF_BURST        "EB"

#define MSG_END_OF_BURST_ACK    "EOB_ACK"       /* EOB_ */
#define TOK_END_OF_BURST_ACK    "EA"

#define MSG_PROTO               "PROTO"         /* PROTO */
#define TOK_PROTO               "PROTO"         /* PROTO */


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
