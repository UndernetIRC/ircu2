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
 */

#ifndef MSG_H
#define MSG_H

/*=============================================================================
 * General defines
 */

#define MAXPARA	   15

/*-----------------------------------------------------------------------------
 * Macro's
 */

/*
 * Tokenization:
 * Each command must have a TOK_COMMAND and MSG_COMMAND definition.
 * If you don't want one or the other, make them the same.
 * Also each command has a "msgclass" used for debugging purposes.
 */

/* *INDENT-OFF* */

#define MSG_PRIVATE		"PRIVMSG"	/* PRIV */
#define TOK_PRIVATE		"P"
#define CLASS_PRIVATE		LEVEL_PROPAGATE

#define MSG_WHO			"WHO"		/* WHO	-> WHOC */
#define TOK_WHO			"H"
#define CLASS_WHO		LEVEL_QUERY

#define MSG_WHOIS		"WHOIS"		/* WHOI */
#define TOK_WHOIS		"W"
#define CLASS_WHOIS		LEVEL_QUERY

#define MSG_WHOWAS		"WHOWAS"	/* WHOW */
#define TOK_WHOWAS		"X"
#define CLASS_WHOWAS		LEVEL_QUERY

#define MSG_USER		"USER"		/* USER */
#define TOK_USER		"USER"
#define CLASS_USER		LEVEL_CLIENT

#define MSG_NICK		"NICK"		/* NICK */
#define TOK_NICK		"N"
#define CLASS_NICK		LEVEL_CLIENT

#define MSG_SERVER		"SERVER"	/* SERV */
#define TOK_SERVER		"S"
#define CLASS_SERVER		LEVEL_MAP

#define MSG_LIST		"LIST"		/* LIST */
#define TOK_LIST		"LIST"
#define CLASS_LIST		LEVEL_QUERY

#define MSG_TOPIC		"TOPIC"		/* TOPI */
#define TOK_TOPIC		"T"
#define CLASS_TOPIC		LEVEL_PROPAGATE

#define MSG_INVITE		"INVITE"	/* INVI */
#define TOK_INVITE		"I"
#define CLASS_INVITE		LEVEL_MODE

#define MSG_VERSION		"VERSION"	/* VERS */
#define TOK_VERSION		"V"
#define CLASS_VERSION		LEVEL_QUERY

#define MSG_QUIT		"QUIT"		/* QUIT */
#define TOK_QUIT		"Q"
#define CLASS_QUIT		LEVEL_CLIENT

#define MSG_SQUIT		"SQUIT"		/* SQUI */
#define TOK_SQUIT		"SQ"
#define CLASS_SQUIT		LEVEL_MAP

#define MSG_KILL		"KILL"		/* KILL */
#define TOK_KILL		"D"
#define CLASS_KILL		LEVEL_CLIENT

#define MSG_INFO		"INFO"		/* INFO */
#define TOK_INFO		"F"
#define CLASS_INFO		LEVEL_QUERY

#define MSG_LINKS		"LINKS"		/* LINK */
#define TOK_LINKS		"LI"
#define CLASS_LINKS		LEVEL_QUERY

#define MSG_STATS		"STATS"		/* STAT */
#define TOK_STATS		"R"
#define CLASS_STATS		LEVEL_QUERY

#define MSG_HELP		"HELP"		/* HELP */
#define TOK_HELP		"HELP"
#define CLASS_HELP		LEVEL_QUERY

#define MSG_ERROR		"ERROR"		/* ERRO */
#define TOK_ERROR		"Y"
#define CLASS_ERROR		LEVEL_PROPAGATE

#define MSG_AWAY		"AWAY"		/* AWAY */
#define TOK_AWAY		"A"
#define CLASS_AWAY		LEVEL_PROPAGATE

#define MSG_CONNECT		"CONNECT"	/* CONN */
#define TOK_CONNECT		"CO"
#define CLASS_CONNECT		LEVEL_PROPAGATE

#define MSG_UPING		"UPING"		/* UPIN */
#define TOK_UPING		"UP"
#define CLASS_UPING		LEVEL_PROPAGATE

#define MSG_MAP			"MAP"		/* MAP	*/
#define TOK_MAP			"MAP"
#define CLASS_MAP		LEVEL_QUERY

#define MSG_PING		"PING"		/* PING */
#define TOK_PING		"G"
#define CLASS_PING		LEVEL_PROPAGATE

#define MSG_PONG		"PONG"		/* PONG */
#define TOK_PONG		"Z"
#define CLASS_PONG		LEVEL_CLIENT

#define MSG_OPER		"OPER"		/* OPER */
#define TOK_OPER		"OPER"
#define CLASS_OPER		LEVEL_PROPAGATE

#define MSG_PASS		"PASS"		/* PASS */
#define TOK_PASS		"PA"
#define CLASS_PASS		LEVEL_CLIENT

#define MSG_WALLOPS		"WALLOPS"	/* WALL */
#define TOK_WALLOPS		"WA"
#define CLASS_WALLOPS		LEVEL_PROPAGATE

#define MSG_DESYNCH             "DESYNCH"       /* DESY */
#define TOK_DESYNCH             "DS"
#define CLASS_DESYNCH           LEVEL_PROPAGATE

#define MSG_TIME		"TIME"		/* TIME */
#define TOK_TIME		"TI"
#define CLASS_TIME		LEVEL_QUERY

#define MSG_SETTIME		"SETTIME"	/* SETT */
#define TOK_SETTIME		"SE"
#define CLASS_SETTIME		LEVEL_PROPAGATE

#define MSG_RPING		"RPING"		/* RPIN */
#define TOK_RPING		"RI"
#define CLASS_RPING		LEVEL_PROPAGATE

#define MSG_RPONG		"RPONG"		/* RPON */
#define TOK_RPONG		"RO"
#define CLASS_RPONG		LEVEL_PROPAGATE

#define MSG_NAMES		"NAMES"		/* NAME */
#define TOK_NAMES		"E"
#define CLASS_NAMES		LEVEL_QUERY

#define MSG_ADMIN		"ADMIN"		/* ADMI */
#define TOK_ADMIN		"AD"
#define CLASS_ADMIN		LEVEL_QUERY

#define MSG_TRACE		"TRACE"		/* TRAC */
#define TOK_TRACE		"TR"
#define CLASS_TRACE		LEVEL_PROPAGATE

#define MSG_NOTICE		"NOTICE"	/* NOTI */
#define TOK_NOTICE		"O"
#define CLASS_NOTICE		LEVEL_PROPAGATE

#define MSG_WALLCHOPS		"WALLCHOPS"	/* WC */
#define TOK_WALLCHOPS		"WC"
#define CLASS_WALLCHOPS		LEVEL_PROPAGATE

#define MSG_CPRIVMSG		"CPRIVMSG"	/* CPRI */
#define TOK_CPRIVMSG		"CP"
#define CLASS_CPRIVMSG		LEVEL_CLIENT

#define MSG_CNOTICE		"CNOTICE"	/* CNOT */
#define TOK_CNOTICE		"CN"
#define CLASS_CNOTICE		LEVEL_CLIENT

#define MSG_JOIN		"JOIN"		/* JOIN */
#define TOK_JOIN		"J"
#define CLASS_JOIN		LEVEL_CHANNEL

#define MSG_PART		"PART"		/* PART */
#define TOK_PART		"L"
#define CLASS_PART		LEVEL_CHANNEL

#define MSG_LUSERS		"LUSERS"	/* LUSE */
#define TOK_LUSERS		"LU"
#define CLASS_LUSERS		LEVEL_QUERY

#define MSG_MOTD		"MOTD"		/* MOTD */
#define TOK_MOTD		"MO"
#define CLASS_MOTD		LEVEL_QUERY

#define MSG_MODE		"MODE"		/* MODE */
#define TOK_MODE		"M"
#define CLASS_MODE		LEVEL_MODE

#define MSG_KICK		"KICK"		/* KICK */
#define TOK_KICK		"K"
#define CLASS_KICK		LEVEL_CHANNEL

#define MSG_USERHOST		"USERHOST"	/* USER -> USRH */
#define TOK_USERHOST		"USERHOST"
#define CLASS_USERHOST		LEVEL_QUERY

#define MSG_USERIP		"USERIP"	/* USER -> USIP */
#define TOK_USERIP		"USERIP"
#define CLASS_USERIP		LEVEL_QUERY

#define MSG_ISON		"ISON"		/* ISON */
#define TOK_ISON		"ISON"
#define CLASS_ISON		LEVEL_QUERY

#define MSG_SQUERY		"SQUERY"	/* SQUE */
#define TOK_SQUERY		"SQUERY"
#define CLASS_SQUERY		LEVEL_QUERY

#define MSG_SERVLIST		"SERVLIST"	/* SERV -> SLIS */
#define TOK_SERVLIST		"SERVSET"
#define CLASS_SERVLIST		LEVEL_QUERY

#define MSG_SERVSET		"SERVSET"	/* SERV -> SSET */
#define TOK_SERVSET		"SERVSET"
#define CLASS_SERVSET		LEVEL_CLIENT

#define MSG_REHASH		"REHASH"	/* REHA */
#define TOK_REHASH		"REHASH"
#define CLASS_REHASH		LEVEL_MAP

#define MSG_RESTART		"RESTART"	/* REST */
#define TOK_RESTART		"RESTART"
#define CLASS_RESTART		LEVEL_MAP

#define MSG_CLOSE		"CLOSE"		/* CLOS */
#define TOK_CLOSE		"CLOSE"
#define CLASS_CLOSE		LEVEL_CLIENT

#define MSG_DIE			"DIE"		/* DIE	*/
#define TOK_DIE			"DIE"
#define CLASS_DIE		LEVEL_MAP

#define MSG_HASH		"HASH"		/* HASH */
#define TOK_HASH		"HASH"
#define CLASS_HASH		LEVEL_QUERY

#define MSG_DNS			"DNS"		/* DNS	-> DNSS */
#define TOK_DNS			"DNS"
#define CLASS_DNS		LEVEL_QUERY

#define MSG_SILENCE		"SILENCE"	/* SILE */
#define TOK_SILENCE		"U"
#define CLASS_SILENCE		LEVEL_PROPAGATE

#define MSG_GLINE		"GLINE"		/* GLIN */
#define TOK_GLINE		"GL"
#define CLASS_GLINE		LEVEL_CLIENT

#define MSG_BURST		"BURST"		/* BURS */
#define TOK_BURST		"B"
#define CLASS_BURST		LEVEL_CHANNEL

#define MSG_CREATE		"CREATE"	/* CREA */
#define TOK_CREATE		"C"
#define CLASS_CREATE		LEVEL_CHANNEL

#define MSG_DESTRUCT		"DESTRUCT"	/* DEST */
#define TOK_DESTRUCT		"DE"
#define CLASS_DESTRUCT		LEVEL_CHANNEL

#define MSG_END_OF_BURST	"END_OF_BURST"	/* END_ */
#define TOK_END_OF_BURST	"EB"
#define CLASS_END_OF_BURST	LEVEL_MAP

#define MSG_END_OF_BURST_ACK	"EOB_ACK"	/* EOB_ */
#define TOK_END_OF_BURST_ACK	"EA"
#define CLASS_END_OF_BURST_ACK	LEVEL_MAP

/* *INDENT-ON* */

/*=============================================================================
 * Constants
 */
#define   MFLG_SLOW              0x01	/* Command can be executed roughly    *
					 * once per 2 seconds.                */
#define   MFLG_UNREG             0x02	/* Command available to unregistered  *
					 * clients.                           */

/*=============================================================================
 * Structures
 */

struct Message {
  unsigned int msgclass;
  char *cmd;
  char *tok;
  int (*func) (aClient *cptr, aClient *sptr, int parc, char *parv[]);
  /* cptr = Connected client ptr
     sptr = Source client ptr
     parc = parameter count
     parv = parameter variable array */
  unsigned int count;
  unsigned int parameters;
  unsigned char flags;		/* bit 0 set means that this command is allowed
				   to be used only on the average of once per 2
				   seconds -SRB */
  unsigned int bytes;
};

struct MessageTree {
  char *final;
  struct Message *msg;
  struct MessageTree *pointers[26];
};

/*=============================================================================
 * Proto types
 */

extern struct Message msgtab[];

#endif /* MSG_H */
