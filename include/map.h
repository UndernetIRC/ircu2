/*
 * map.h
 *
 * $Id$
 */
#ifndef INCLUDED_map_h
#define INCLUDED_map_h

struct Client;

/*
 * Prototypes
 */

void dump_map(struct Client *cptr, struct Client *server, char *mask, int prompt_length);

#endif /* INCLUDED_map_h */
