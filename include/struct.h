/*
 * IRC - Internet Relay Chat, include/struct.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 1996 -1997 Carlo Wood
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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

#ifndef STRUCT_H
#define STRUCT_H

#include <netinet/in.h>		/* Needed for struct in_addr */
#include "whowas.h"		/* Needed for whowas struct */

#ifndef INCLUDED_dbuf_h
#include "dbuf.h"
#endif


/*=============================================================================
 * General defines
 */

#define NICKLEN		9
#define USERLEN		10
#define HOSTLEN		63
#define REALLEN		50
#define PASSWDLEN	20
#define BUFSIZE		512	/* WARNING: *DONT* CHANGE THIS!!!! */
#define MAXTARGETS	20
#define STARTTARGETS	10
#define RESERVEDTARGETS 12

/*-----------------------------------------------------------------------------
 * Macro's
 */

#define CLIENT_LOCAL_SIZE sizeof(aClient)
#define CLIENT_REMOTE_SIZE offsetof(aClient, count)

#define MyConnect(x)	((x)->from == (x))
#define MyUser(x)	(MyConnect(x) && IsUser(x))
#define MyOper(x)	(MyConnect(x) && IsOper(x))
#define Protocol(x)	((x)->serv->prot)

/*=============================================================================
 * Structures
 *
 * Only put structures here that are being used in a very large number of
 * source files. Other structures go in the header file of there corresponding
 * source file, or in the source file itself (when only used in that file).
 */

struct Client {
  struct Client *next, *prev, *hnext;
  struct User *user;		/* ...defined, if this is a User */
  struct Server *serv;		/* ...defined, if this is a server */
  struct Whowas *whowas;	/* Pointer to ww struct to be freed on quit */
  char yxx[4];			/* Numeric Nick: YMM if this is a server,
				   XX0 if this is a user */
  time_t lasttime;		/* ...should be only LOCAL clients? --msa */
  time_t firsttime;		/* time client was created */
  time_t since;			/* last time we parsed something */
  time_t lastnick;		/* TimeStamp on nick */
  int marker;			/* /who processing marker */
  unsigned int flags;		/* client flags */
  struct Client *from;		/* == self, if Local Client, *NEVER* NULL! */
  int fd;			/* >= 0, for local clients */
  unsigned int hopcount;	/* number of servers to this 0 = local */
  short status;			/* Client type */
  struct in_addr ip;		/* Real ip# - NOT defined for remote servers! */
  char name[HOSTLEN + 1];	/* Unique name of the client, nick or host */
  char username[USERLEN + 1];	/* username here now for auth stuff */
  char info[REALLEN + 1];	/* Free form additional client information */
  /*
   *  The following fields are allocated only for local clients
   *  (directly connected to *this* server with a socket.
   *  The first of them *MUST* be the "count"--it is the field
   *  to which the allocation is tied to! *Never* refer to
   *  these fields, if (from != self).
   */
  unsigned int count;		/* Amount of data in buffer, DON'T PUT
				   variables ABOVE this one! */
  snomask_t snomask;		/* mask for server messages */
  char buffer[BUFSIZE];		/* Incoming message buffer; or the error that
				   caused this clients socket to be `dead' */
  unsigned short int lastsq;	/* # of 2k blocks when sendqueued called last */
  time_t nextnick;		/* Next time that a nick change is allowed */
  time_t nexttarget;		/* Next time that a target change is allowed */
  unsigned char targets[MAXTARGETS];	/* Hash values of current targets */
  unsigned int cookie;		/* Random number the user must PONG */
  struct DBuf sendQ;		/* Outgoing message queue--if socket full */
  struct DBuf recvQ;		/* Hold for data incoming yet to be parsed */
  unsigned int sendM;		/* Statistics: protocol messages send */
  unsigned int sendK;		/* Statistics: total k-bytes send */
  unsigned int receiveM;	/* Statistics: protocol messages received */
  unsigned int receiveK;	/* Statistics: total k-bytes received */
  unsigned short int sendB;	/* counters to count upto 1-k lots of bytes */
  unsigned short int receiveB;	/* sent and received. */
  struct Client *acpt;		/* listening client which we accepted from */
  struct SLink *confs;		/* Configuration record associated */
  int authfd;			/* fd for rfc931 authentication */
  unsigned short int port;	/* and the remote port# too :-) */
  struct hostent *hostp;
  struct ListingArgs *listing;
#ifdef	pyr
  struct timeval lw;
#endif
  char sockhost[HOSTLEN + 1];	/* This is the host name from the socket and
				   after which the connection was accepted. */
  char passwd[PASSWDLEN + 1];
};

struct Server {
  struct Server *nexts;
  struct Client *up;		/* Server one closer to me */
  struct DSlink *down;		/* List with downlink servers */
  struct DSlink *updown;	/* own Dlink in up->serv->down struct */
  aClient **client_list;	/* List with client pointers on this server */
  struct User *user;		/* who activated this connection */
  struct ConfItem *nline;	/* N-line pointer for this server */
  time_t timestamp;		/* Remotely determined connect try time */
  time_t ghost;			/* Local time at which a new server
				   caused a Ghost */
  unsigned short prot;		/* Major protocol */
  unsigned short nn_last;	/* Last numeric nick for p9 servers only */
  unsigned int nn_mask;		/* [Remote] FD_SETSIZE - 1 */
  char nn_capacity[4];		/* numeric representation of server capacity */
#ifdef	LIST_DEBUG
  struct Client *bcptr;
#endif
  char *last_error_msg;		/* Allocated memory with last message receive with an ERROR */
  char by[NICKLEN + 1];
};

struct User {
  struct User *nextu;
  struct Client *server;	/* client structure of server */
  struct SLink *channel;	/* chain of channel pointer blocks */
  struct SLink *invited;	/* chain of invite pointer blocks */
  struct SLink *silence;	/* chain of silence pointer blocks */
  char *away;			/* pointer to away message */
  time_t last;
  unsigned int refcnt;		/* Number of times this block is referenced */
  unsigned int joined;		/* number of channels joined */
  char username[USERLEN + 1];
  char host[HOSTLEN + 1];
#ifdef LIST_DEBUG
  struct Client *bcptr;
#endif
};

#endif /* STRUCT_H */
