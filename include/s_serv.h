/** @file s_serv.h
 * @brief Miscellaneous server support functions.
 * @version $Id$
 */
#ifndef INCLUDED_s_serv_h
#define INCLUDED_s_serv_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct ConfItem;
struct Client;

extern unsigned int max_connection_count;
extern unsigned int max_client_count;

/*
 * Prototypes
 */
extern int exit_new_server(struct Client* cptr, struct Client* sptr,
                           const char* host, time_t timestamp, const char* fmt, ...);
extern int a_kills_b_too(struct Client *a, struct Client *b);
extern int server_estab(struct Client *cptr, struct ConfItem *aconf);
extern void assign_sid(struct Client *new_server);
extern void compute_secure_path_groups(void);
extern int is_secure_path(struct Client *c1, struct Client *c2);
extern int get_secure_group_id(struct Client *cli);


#endif /* INCLUDED_s_serv_h */
