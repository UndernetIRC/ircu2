/** @file crule.h
 * @brief Interfaces and declarations for connection rule checking.
 */
#ifndef INCLUDED_crule_h
#define INCLUDED_crule_h

/*
 * opaque node pointer
 */
struct CRuleNode;

extern int crule_eval(struct CRuleNode* rule);
extern char *crule_text(struct CRuleNode *rule);

extern struct CRuleNode* crule_make_and(struct CRuleNode *left,
                                        struct CRuleNode *right);
extern struct CRuleNode* crule_make_or(struct CRuleNode *left,
                                       struct CRuleNode *right);
extern struct CRuleNode* crule_make_not(struct CRuleNode *arg);
extern struct CRuleNode* crule_make_connected(char *arg);
extern struct CRuleNode* crule_make_directcon(char *arg);
extern struct CRuleNode* crule_make_via(char *neighbor,
                                        char *server);
extern struct CRuleNode* crule_make_directop(void);
extern void crule_free(struct CRuleNode* elem);

#endif /* INCLUDED_crule_h */
