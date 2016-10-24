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
 */
/** @file
 * @brief Declarations and interfaces for handling connection classes.
 * @version $Id$
 */
#ifndef INCLUDED_class_h
#define INCLUDED_class_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#include "client.h"

struct ConfItem;
struct StatDesc;

/*
 * Structures
 */
/** Represents a connection class. */
struct ConnectionClass {
  struct ConnectionClass* next;           /**< Link to next connection class. */
  char                    *cc_name;       /**< Name of connection class. */
  char                    *default_umode; /**< Default usermode for users
                                             in this class. */
  struct Privs            privs;          /**< Privilege bits that are set on
                                             or off. */
  struct Privs            privs_dirty;    /**< Indication of which bits in
                                             ConnectionClass::privs are valid. */
  unsigned int            max_sendq;      /**< Maximum client SendQ in bytes. */
  unsigned int            max_links;      /**< Maximum connections allowed. */
  unsigned int            ref_count;      /**< Number of references to class. */
  unsigned short          ping_freq;      /**< Ping frequency for clients. */
  unsigned short          conn_freq;      /**< Auto-connect frequency. */
  unsigned char           valid;          /**< Valid flag (cleared after this
                                             class is removed from the config).*/
};

/*
 * Macro's
 */

/** Get class name for \a x. */
#define ConClass(x)     ((x)->cc_name)
/** Get ping frequency for \a x. */
#define PingFreq(x)     ((x)->ping_freq)
/** Get connection frequency for \a x. */
#define ConFreq(x)      ((x)->conn_freq)
/** Get maximum links allowed for \a x. */
#define MaxLinks(x)     ((x)->max_links)
/** Get maximum SendQ size for \a x. */
#define MaxSendq(x)     ((x)->max_sendq)
/** Get number of references to \a x. */
#define Links(x)        ((x)->ref_count)
/** Get default usermode for \a x. */
#define CCUmode(x)      ((x)->default_umode)

/** Get class name for ConfItem \a x. */
#define ConfClass(x)    ((x)->conn_class->cc_name)
/** Get ping frequency for ConfItem \a x. */
#define ConfPingFreq(x) ((x)->conn_class->ping_freq)
/** Get connection frequency for ConfItem \a x. */
#define ConfConFreq(x)  ((x)->conn_class->conn_freq)
/** Get maximum links allowed for ConfItem \a x. */
#define ConfMaxLinks(x) ((x)->conn_class->max_links)
/** Get maximum SendQ size for ConfItem \a x. */
#define ConfSendq(x)    ((x)->conn_class->max_sendq)
/** Get number of references to class in ConfItem \a x. */
#define ConfLinks(x)    ((x)->conn_class->ref_count)
/** Get default usermode for ConfItem \a x. */
#define ConfUmode(x)    ((x)->conn_class->default_umode)
/** Find a valid configuration class by name. */
#define find_class(name) do_find_class((name), 0)

/*
 * Proto types
 */

extern void init_class(void);

extern const struct ConnectionClass* get_class_list(void);
extern void class_mark_delete(void);
extern void class_delete_marked(void);

extern struct ConnectionClass *do_find_class(const char *name, int extras);
extern struct ConnectionClass *make_class(void);
extern void free_class(struct ConnectionClass * tmp);
extern char *get_conf_class(const struct ConfItem *aconf);
extern int get_conf_ping(const struct ConfItem *aconf);
extern char *get_client_class(struct Client *acptr);
extern void add_class(char *name, unsigned int ping,
                      unsigned int confreq, unsigned int maxli,
                      unsigned int sendq);
extern void report_classes(struct Client *sptr, const struct StatDesc *sd,
                           char *param);
extern unsigned int get_sendq(struct Client* cptr);

extern void class_send_meminfo(struct Client* cptr);
#endif /* INCLUDED_class_h */
