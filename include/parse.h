#ifndef PARSE_H
#define PARSE_H

/*=============================================================================
 * Proto types
 */

extern int parse_client(aClient *cptr, char *buffer, char *bufend);
extern int parse_server(aClient *cptr, char *buffer, char *bufend);
extern void initmsgtree(void);

#endif /* PARSE_H */
