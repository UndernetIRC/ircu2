/*
 * IRC - Internet Relay Chat, include/ircd_defs.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 *
 * Commentary by Bleep (Thomas Helvey)
 *
 * $Id$
 */
#ifndef INCLUDED_ircd_defs_h
#define INCLUDED_ircd_defs_h
/*
 * Definitions used everywhere in the server
 * NOTE: Changing any of these definitions is equivalent to a protocol
 * revision. Every server on a given network must also use the same sizes.
 */

/*
 * NICKLEN is the maximum length allowed for a nickname
 *
 * Because certain networks are very helpful in finding bugs, the below
 * is a default that can easily be overridden in CFLAGS.  Just add 
 * -DNICKLEN=15 to CFLAGS and save your config in .., and you can forget about
 * it.  Thanks for helping debug guys.
 */
#ifndef NICKLEN
#define NICKLEN         9
#endif
/*
 * USERLEN is the maximum length allowed of a user name including an optional
 * leading '~' if the user name has not been authenticated by an auth (RFC 931)
 * server query.
 */
#define USERLEN         10
/*
 * HOSTLEN is exactly long enough to hold one (1) segment of FQDN or hostname.
 * This is due to an historical misinterpretation of RFC 1034.
 * 3.1. Name space specifications and terminology
 *
 * The domain name space is a tree structure.  Each node and leaf on the
 * tree corresponds to a resource set (which may be empty).  The domain
 * system makes no distinctions between the uses of the interior nodes and
 * leaves, and this memo uses the term "node" to refer to both.
 *
 * Each node has a label, which is zero to 63 octets in length.  Brother
 * nodes may not have the same label, although the same label can be used
 * for nodes which are not brothers.  One label is reserved, and that is
 * the null (i.e., zero length) label used for the root.
 *
 * This has proven not to be a problem in the past as connections with FQDN's
 * of greater than 63 characters are rejected by the server, and most FQDN's
 * are shorter. It is possible to have a valid FQDN longer than 63 characters.
 */
#define HOSTLEN         63
/*
 * ACCOUNTLEN is the maximum length for the account name, which can be set
 * with the ACCOUNT (AC) command.  This is used for keeping track of who's
 * logged into which account, for the benefit of irc services.
 */
#define ACCOUNTLEN      12
/*
 * REALLEN is the maximum length for user supplied information about a client
 * connection (gcos). This information is set at client/server registration
 * time.
 */
#define REALLEN         50
/*
 * PASSWDLEN is the maximum length for a password used for connecting servers
 * and clients.
 */
#define PASSWDLEN       20
/*
 * SOCKIPLEN is the length of a dotted quad ip address "XXX.XXX.XXX.XXX"
 */
#define SOCKIPLEN 15
/*
 * TOPICLEN is the maximum length for channel topics and kill comments
 */
#define TOPICLEN        160
/*
 * AWAYLEN is the maximum length for away messages
 */
#define AWAYLEN		160
/*
 * BUFSIZE is exactly long enough to hold one protocol message (RFC 1459)
 * including the line termination (\r\n).
 */
#define BUFSIZE         512     /* WARNING: *DONT* CHANGE THIS!!!! */

#define MAXTARGETS      20
#define STARTTARGETS    10
#define RESERVEDTARGETS 12

#endif /* INCLUDED_ircd_defs_h */

