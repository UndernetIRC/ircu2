/************************************************************************
 *   IRC - Internet Relay Chat, include/s_auth.h
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Interface for DNS and ident lookups.
 * @version $Id$
 */
#ifndef INCLUDED_s_auth_h
#define INCLUDED_s_auth_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_ircd_events_h
#include "ircd_events.h"
#endif

struct Client;
struct AuthRequest;
struct StatDesc;

extern void start_auth(struct Client *);
extern int auth_ping_timeout(struct Client *);
extern int auth_set_pong(struct AuthRequest *auth, unsigned int cookie);
extern int auth_set_user(struct AuthRequest *auth, const char *username, const char *hostname, const char *servername, const char *userinfo);
extern int auth_set_nick(struct AuthRequest *auth, const char *nickname);
extern int auth_set_password(struct AuthRequest *auth, const char *password);
extern int auth_cap_start(struct AuthRequest *auth);
extern int auth_cap_done(struct AuthRequest *auth);
extern int auth_spoof_user(struct AuthRequest *auth, const char *username, const char *hostname, const char *ip);
extern void destroy_auth_request(struct AuthRequest *req);

extern int auth_spawn(int argc, char *argv[]);
extern void auth_send_exit(struct Client *cptr);
extern void auth_send_xreply(struct Client *sptr, const char *routing, const char *reply);
extern void auth_mark_closing(void);
extern void auth_close_unused(void);
extern void report_iauth_conf(struct Client *cptr, const struct StatDesc *sd, char *param);
extern void report_iauth_stats(struct Client *cptr, const struct StatDesc *sd, char *param);

#endif /* INCLUDED_s_auth_h */

