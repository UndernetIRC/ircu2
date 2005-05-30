/** @file list.h
 * @brief Singly and doubly linked list manipulation interface.
 * @version $Id$
 */
#ifndef INCLUDED_list_h
#define INCLUDED_list_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>         /* time_t, size_t */
#define INCLUDED_sys_types_h
#endif

struct Client;
struct Connection;
struct Channel;
struct ConfItem;

/*
 * Structures
 */

/** Node in a singly linked list. */
struct SLink {
  struct SLink *next; /**< Next element in list. */
  union {
    struct Client *cptr;    /**< List element as a client. */
    struct Channel *chptr;  /**< List element as a channel. */
    struct ConfItem *aconf; /**< List element as a configuration item. */
    char *cp;               /**< List element as a string. */
  } value;                  /**< Value of list element. */
  unsigned int flags;       /**< Modifier flags for list element. */
};

/** Node in a doubly linked list. */
struct DLink {
  struct DLink*  next;      /**< Next element in list. */
  struct DLink*  prev;      /**< Previous element in list. */
  union {
    struct Client*  cptr;   /**< List element as a client. */
    struct Channel* chptr;  /**< List element as a channel. */
    char*           ch;     /**< List element as a string. */
  } value;                  /**< Value of list element. */
};

/*
 * Proto types
 */

extern void free_link(struct SLink *lp);
extern struct SLink *make_link(void);
extern void init_list(void);
extern struct Client *make_client(struct Client *from, int status);
extern void free_connection(struct Connection *con);
extern void free_client(struct Client *cptr);
extern struct Server *make_server(struct Client *cptr);
extern void remove_client_from_list(struct Client *cptr);
extern void add_client_to_list(struct Client *cptr);
extern struct DLink *add_dlink(struct DLink **lpp, struct Client *cp);
extern void remove_dlink(struct DLink **lpp, struct DLink *lp);
extern struct ConfItem *make_conf(int type);
extern void free_conf(struct ConfItem *aconf);
extern void send_listinfo(struct Client *cptr, char *name);

#endif /* INCLUDED_list_h */
