#ifndef CRULE_H
#define CRULE_H

/*=============================================================================
 * Proto types
 */

extern void crule_free(char **elem);
extern int crule_eval(char *rule);
extern char *crule_parse(char *rule);

#endif /* CRULE_H */
