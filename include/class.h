/*
 * IRC - Internet Relay Chat, include/class.h
 * Copyright (C) 1990 Darren Reed
 * Copyright (C) 1996 - 1997 Carlo Wood
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
 * $Id$
 */
#ifndef INCLUDED_class_h
#define INCLUDED_class_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct Client;
struct StatDesc;
struct ConfItem;

/*
 * Structures
 */
struct ConnectionClass {
  struct ConnectionClass* next;
  int                     cc_class;
  unsigned int            max_sendq;
  short                   ping_freq;
  short                   conn_freq;
  short                   max_links;
  unsigned char           valid;
  int                     ref_count;
};

/*
 * Macro's
 */

#define ConClass(x)     ((x)->cc_class)
#define PingFreq(x)     ((x)->ping_freq)
#define ConFreq(x)      ((x)->conn_freq)
#define MaxLinks(x)     ((x)->max_links)
#define MaxSendq(x)     ((x)->max_sendq)
#define Links(x)        ((x)->ref_count)

#define ConfClass(x)    ((x)->conn_class->cc_class)
#define ConfPingFreq(x) ((x)->conn_class->ping_freq)
#define ConfConFreq(x)  ((x)->conn_class->conn_freq)
#define ConfMaxLinks(x) ((x)->conn_class->max_links)
#define ConfSendq(x)    ((x)->conn_class->max_sendq)
#define ConfLinks(x)    ((x)->conn_class->ref_count)

/*
 * Proto types
 */

extern void init_class(void);

extern const struct ConnectionClass* get_class_list(void);
extern void class_mark_delete(void);
extern void class_delete_marked(void);

extern struct ConnectionClass *find_class(unsigned int cclass);
extern struct ConnectionClass *make_class(void);
extern void free_class(struct ConnectionClass * tmp);
extern unsigned int get_con_freq(struct ConnectionClass * clptr);
extern unsigned int get_conf_class(const struct ConfItem *aconf);
extern int get_conf_ping(const struct ConfItem *aconf);
extern unsigned int get_client_class(struct Client *acptr);
extern void add_class(unsigned int conclass, unsigned int ping,
                      unsigned int confreq, unsigned int maxli, unsigned int sendq);
extern void check_class(void);
extern void report_classes(struct Client *sptr, struct StatDesc *sd, int stat,
			   char *param);
extern unsigned int get_sendq(struct Client* cptr);

extern void class_send_meminfo(struct Client* cptr);
#endif /* INCLUDED_class_h */
