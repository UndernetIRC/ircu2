/**
 * @file
 * @brief Connection rule parser and checker
 * @version $Id$
 *
 * by Tony Vencill (Tonto on IRC) <vencill@bga.com>
 * rewritten by Michael Poole <mdpoole@troilus.org>
 *
 * This used to have a recursive descent parser and debugging helper
 * code.  That all got ripped out and moved into the config parser.
 */

#include "config.h"
#include "crule.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h" /* for assert() */
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "list.h"
#include "match.h"
#include "s_bsd.h"
#include "struct.h"

/** Evaluation function for a connection rule. */
typedef int (*crule_funcptr) (struct CRuleNode *);

/** Node in a connection rule tree. */
struct CRuleNode {
  crule_funcptr funcptr; /**< Evaluation function for this node. */
  int numargs;           /**< Number of arguments. */
  void *arg[1];          /**< Array of arguments.  For operators, each arg
                            is a tree element; for functions, each arg is
                            a string. */
};

/** Create a CRuleNode.
 * @param[in] funcptr Evaluation function for the node.
 * @param[in] numargs Number of arguments.
 * @param[in] ... Arguments as void pointers.
 * @return Newly allocated CRuleNode.
 */
static struct CRuleNode *crule_make(crule_funcptr funcptr, int numargs, ...)
{
  struct CRuleNode *res;
  va_list va;
  int ii;

  /* be sure we allocate at least sizeof(struct CRuleNode) */
  if (numargs > 0)
    res = MyMalloc(sizeof(*res) + sizeof(res->arg[0]) * (numargs - 1));
  else
    res = MyMalloc(sizeof(*res));
  res->funcptr = funcptr;
  res->numargs = numargs;
  va_start(va, numargs);
  for (ii = 0; ii < numargs; ++ii)
    res->arg[ii] = va_arg(va, void*);
  va_end(va);
  return res;
}

/** Find any linked server with a name matching \a mask behind \a start.
 * @param[in] mask Server name mask to search for.
 * @param[in] start Server at which to start search.
 * @return A pointer to a server matching \a mask, or NULL if none exist.
 */
static int crule_connected_from(const char *mask, struct Client *start)
{
  struct DLink *dl;

  assert(cli_serv(start) != NULL);

  for (dl = cli_serv(start)->down; dl; dl = dl->next)
    if (match(mask, cli_name(dl->value.cptr))
        || crule_connected_from(mask, dl->value.cptr))
      return 1;

  return 0;
}

/** Check whether any connected server matches \a rule->arg[0].
 * @param[in] rule The rule to evaluate.
 * @return Non-zero if the condition is true, zero if not.
 */
static int crule_connected(struct CRuleNode *rule)
{
  assert(rule->numargs == 1);

  return crule_connected_from(rule->arg[0], &me);
}

/** Check whether any directly connected server matches \a rule->arg[0].
 * @param[in] rule The rule to evaluate.
 * @return Non-zero if the condition is true, zero if not.
 */
static int crule_directcon(struct CRuleNode *rule)
{
  struct DLink *dl;

  assert(rule->numargs == 1);

  for (dl = cli_serv(&me)->down; dl; dl = dl->next)
    if (match(rule->arg[0], cli_name(dl->value.cptr)))
      return 1;

  return 0;
}

/** Check whether a connected server matching \a rule->arg[1] is
 * connnected to me behind one matching \a rule->arg[0].
 * @param[in] rule The rule to evaluate.
 * @return Non-zero if the condition is true, zero if not.
 */
static int crule_via(struct CRuleNode *rule)
{
  struct DLink *dl;

  assert(rule->numargs == 2);

  for (dl = cli_serv(&me)->down; dl; dl = dl->next)
    if (match(rule->arg[0], cli_name(dl->value.cptr))
        && crule_connected_from(rule->arg[1], dl->value.cptr))
      return 1;

  return 0;
}

/** Check whether we have a local IRC operator.
 * @param[in] rule The rule to evaluate.
 * @return Non-zero if the condition is true, zero if not.
 */
static int crule_directop(struct CRuleNode *rule)
{
  struct Client *acptr;
  int i;

  assert(rule->numargs == 0);

  for (i = 0; i <= HighestFd; i++)
    if ((acptr = LocalClientArray[i]) && IsAnOper(acptr))
      return 1;

  return 0;
}

/** Perform an 'and' test on \a rule->arg[0] and \a rule->arg[1].
 * @param[in] rule Rule to evaluate.
 * @return Non-zero if the condition is true, zero if not.
 */
static int crule_and(struct CRuleNode *rule)
{
  assert(rule->numargs == 2);
  return crule_eval(rule->arg[0]) && crule_eval(rule->arg[1]);
}

/** Perform an 'or' test on \a rule->arg[0] and \a rule->arg[1].
 * @param[in] rule Rule to evaluate.
 * @return Non-zero if the condition is true, zero if not.
 */
static int crule_or(struct CRuleNode *rule)
{
  assert(rule->numargs == 2);
  return crule_eval(rule->arg[0]) || crule_eval(rule->arg[1]);
}

/** Invert the logical sense of \a rule->arg[0].
 * @param[in] rule Rule to evaluate.
 * @return Non-zero if the condition is true, zero if not.
 */
static int crule_not(struct CRuleNode *rule)
{
  assert(rule->numargs == 1);
  return !crule_eval(rule->arg[0]);
}

/** Evaluate a connection rule.
 * @param[in] rule Rule to evalute.
 * @return Non-zero if the rule allows the connection, zero otherwise.
 */
int crule_eval(struct CRuleNode* rule)
{
  return (rule->funcptr(rule));
}

/** Free a connection rule and all its children.
 * @param[in] elem Pointer to element to free.
 */
void crule_free(struct CRuleNode* elem)
{
  if (!elem)
      return;
  if (elem->funcptr == crule_not)
  {
    crule_free(elem->arg[0]);
  }
  else if (elem->funcptr == crule_and || elem->funcptr == crule_or)
  {
    crule_free(elem->arg[0]);
    crule_free(elem->arg[1]);
  }
  else
  {
    while (elem->numargs--)
      MyFree(elem->arg[elem->numargs]);
  }
  MyFree(elem);
}

struct CRuleNode *
crule_make_and(struct CRuleNode *left, struct CRuleNode *right)
{
  return crule_make(crule_and, 2, left, right);
}

struct CRuleNode *
crule_make_or(struct CRuleNode *left, struct CRuleNode *right)
{
  return crule_make(crule_or, 2, left, right);
}

struct CRuleNode *
crule_make_not(struct CRuleNode *arg)
{
  return crule_make(crule_not, 1, arg);
}

struct CRuleNode *
crule_make_connected(char *arg)
{
  return crule_make(crule_connected, 1, arg);
}

struct CRuleNode *
crule_make_directcon(char *arg)
{
  return crule_make(crule_directcon, 1, arg);
}

struct CRuleNode *
crule_make_via(char *neighbor, char *server)
{
  return crule_make(crule_via, 2, neighbor, server);
}

struct CRuleNode *
crule_make_directop(void)
{
  return crule_make(crule_directop, 0);
}

static int
crule_cat(struct CRuleNode *rule, char *buf, size_t remain)
{
  if (rule->funcptr == crule_connected) {
    assert(rule->numargs == 1);
    return ircd_snprintf(NULL, buf, remain, "connected(\"%s\")", rule->arg[0]);
  } else if (rule->funcptr == crule_directcon) {
    assert(rule->numargs == 1);
    return ircd_snprintf(NULL, buf, remain, "directcon(\"%s\")", rule->arg[0]);
  } else if (rule->funcptr == crule_via) {
    assert(rule->numargs == 2);
    return ircd_snprintf(NULL, buf, remain, "via(\"%s\", \"%s\")",
                         rule->arg[0], rule->arg[1]);
  } else if (rule->funcptr == crule_directop) {
    assert(rule->numargs == 0);
    return ircd_snprintf(NULL, buf, remain, "directop()", rule->arg[0]);
  } else if (rule->funcptr == crule_and || rule->funcptr == crule_or) {
    const char *op = (rule->funcptr == crule_and) ? " && " : " || ";
    size_t used = 0;

    assert(rule->numargs == 2);
    if (remain > used++)
      buf[used - 1] = '(';
    used += crule_cat(rule->arg[0], buf + used, (remain < used) ? 0 : remain - used);
    if (remain > used)
      used += ircd_snprintf(NULL, buf + used, remain - used, op);
    used += crule_cat(rule->arg[1], buf + used, (remain < used) ? 0 : remain - used);
    if (remain > used++)
      buf[used - 1] = ')';
    buf[used] = '\0';
    return used;
  } else if (rule->funcptr == crule_not) {
    if (remain)
      buf[0] = '!';
    return 1 + crule_cat(rule->arg[0], buf + 1, (remain < 1) ? 0 : remain - 1);
  } else
    return ircd_snprintf(NULL, buf, remain, "???");
}

char *crule_text(struct CRuleNode *rule)
{
  char buf[BUFSIZE], *res;
  buf[sizeof(buf) - 1] = '\0';
  crule_cat(rule, buf, sizeof(buf) - 1);
  return DupString(res, buf);
}
