/*
 * parse.h
 *
 * $Id$
 */
#ifndef INCLUDED_parse_h
#define INCLUDED_parse_h

struct Client;

/*
 * Prototypes
 */

extern int parse_client(struct Client *cptr, char *buffer, char *bufend);
extern int parse_server(struct Client *cptr, char *buffer, char *bufend);
extern void initmsgtree(void);

#endif /* INCLUDED_parse_h */
