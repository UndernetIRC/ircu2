/*
 * crule.h
 *
 * $Id$
 */
#ifndef INCLUDED_crule_h
#define INCLUDED_crule_h

/*
 * Proto types
 */

extern void crule_free(char **elem);
extern int crule_eval(char *rule);
extern char *crule_parse(char *rule);

#endif /* INCLUDED_crule_h */
