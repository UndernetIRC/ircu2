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

/*
 * opaque node pointer
 */
struct CRuleNode;

extern void crule_free(struct CRuleNode** elem);
extern int crule_eval(struct CRuleNode* rule);
extern struct CRuleNode* crule_parse(const char* rule);

#endif /* INCLUDED_crule_h */
