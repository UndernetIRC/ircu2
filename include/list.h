/*
 * list.h
 *
 * $Id$
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

struct SLink {
  struct SLink *next;
  union {
    struct Client *cptr;
    struct Channel *chptr;
    struct ConfItem *aconf;
    char *cp;
    struct {
      char *banstr;
      char *who;
      time_t when;
    } ban;
  } value;
  unsigned int flags;
};

struct DLink {
  struct DLink*  next;
  struct DLink*  prev;
  union {
    struct Client*  cptr;
    struct Channel* chptr;
    char*           ch;
  } value;
};

/*
 * Proto types
 */

extern void free_link(struct SLink *lp);
extern struct SLink *make_link(void);
extern struct SLink *find_user_link(struct SLink *lp, struct Client *ptr);
extern void init_list(void);
extern struct Client *make_client(struct Client *from, int status);
extern void free_connection(struct Connection *con);
extern void free_client(struct Client *cptr);
extern struct Server *make_server(struct Client *cptr);
extern void remove_client_from_list(struct Client *cptr);
extern void add_client_to_list(struct Client *cptr);
extern struct DLink *add_dlink(struct DLink **lpp, struct Client *cp);
extern void remove_dlink(struct DLink **lpp, struct DLink *lp);
extern struct ConfItem *make_conf(void);
extern void delist_conf(struct ConfItem *aconf);
extern void free_conf(struct ConfItem *aconf);
extern void send_listinfo(struct Client *cptr, char *name);

#endif /* INCLUDED_list_h */
