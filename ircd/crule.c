/*
 * SmartRoute phase 1
 * connection rule patch
 * by Tony Vencill (Tonto on IRC) <vencill@bga.com>
 *
 * The majority of this file is a recusive descent parser used to convert
 * connection rules into expression trees when the conf file is read.
 * All parsing structures and types are hidden in the interest of good
 * programming style and to make possible future data structure changes
 * without affecting the interface between this patch and the rest of the
 * server.  The only functions accessible externally are crule_parse,
 * crule_free, and crule_eval.  Prototypes for these functions can be
 * found in h.h.
 *
 * Please direct any connection rule or SmartRoute questions to Tonto on
 * IRC or by email to vencill@bga.com.
 *
 * For parser testing, defining CR_DEBUG generates a stand-alone parser
 * that takes rules from stdin and prints out memory allocation
 * information and the parsed rule.  This stand alone parser is ignorant
 * of the irc server and thus cannot do rule evaluation.  Do not define
 * this flag when compiling the server!  If you wish to generate the
 * test parser, compile from the ircd directory with a line similar to
 * cc -o parser -DCR_DEBUG crule.c
 *
 * The define CR_CHKCONF is provided to generate routines needed in
 * chkconf.  These consist of the parser, a different crule_parse that
 * prints errors to stderr, and crule_free (just for good style and to
 * more closely simulate the actual ircd environment).  crule_eval and
 * the rule functions are made empty functions as in the stand-alone
 * test parser.
 *
 * $Id$
 */
#include "config.h"

#include "crule.h"
#ifndef CR_DEBUG

/* ircd functions and types we need */
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_string.h"
#include "match.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "struct.h"

#include <stdio.h>
#include <stdlib.h>

#else /* includes and defines to make the stand-alone test parser */

#include <stdio.h>
#include <stdlib.h>

#define BadPtr(x) (!(x) || (*(x) == '\0'))
#define DupString(x,y) \
        do { \
          x = (char*) MyMalloc(strlen(y)+1); \
        strcpy(x,y); \
        } while(0)

/* We don't care about collation discrepacies here, it seems.... */
#define ircd_strcmp strcasecmp

#endif

#include <string.h>


#if defined(CR_DEBUG) || defined(CR_CHKCONF)
#undef MyMalloc
#undef malloc
#define MyMalloc malloc
#undef MyFree
#undef free
#define MyFree free
#endif

/* some constants and shared data types */
#define CR_MAXARGLEN 80         /* why 80? why not? it's > hostname lengths */
#define CR_MAXARGS 3            /* There's a better way to do this,
                                   but not now. */

/*
 * Some symbols for easy reading
 */

enum crule_token {
  CR_UNKNOWN, CR_END, CR_AND, CR_OR, CR_NOT, CR_OPENPAREN, CR_CLOSEPAREN,
  CR_COMMA, CR_WORD
};

enum crule_errcode {
  CR_NOERR, CR_UNEXPCTTOK, CR_UNKNWTOK, CR_EXPCTAND, CR_EXPCTOR,
  CR_EXPCTPRIM, CR_EXPCTOPEN, CR_EXPCTCLOSE, CR_UNKNWFUNC, CR_ARGMISMAT
};

/*
 * Expression tree structure, function pointer, and tree pointer local!
 */
typedef int (*crule_funcptr) (int, void **);

struct CRuleNode {
  crule_funcptr funcptr;
  int numargs;
  void *arg[CR_MAXARGS];        /* For operators arg points to a tree element;
                                   for functions arg points to a char string. */
};

typedef struct CRuleNode* CRuleNodePtr;

/* local rule function prototypes */
static int crule_connected(int, void **);
static int crule_directcon(int, void **);
static int crule_via(int, void **);
static int crule_directop(int, void **);
static int crule__andor(int, void **);
static int crule__not(int, void **);

/* local parsing function prototypes */
static int crule_gettoken(int* token, const char** str);
static void crule_getword(char*, int*, size_t, const char**);
static int crule_parseandexpr(CRuleNodePtr*, int *, const char**);
static int crule_parseorexpr(CRuleNodePtr*, int *, const char**);
static int crule_parseprimary(CRuleNodePtr*, int *, const char**);
static int crule_parsefunction(CRuleNodePtr*, int *, const char**);
static int crule_parsearglist(CRuleNodePtr, int *, const char**);

#if defined(CR_DEBUG) || defined(CR_CHKCONF)
/*
 * Prototypes for the test parser; if not debugging,
 * these are defined in h.h
 */
struct CRuleNode* crule_parse(const char*);
void crule_free(struct CRuleNode**);
#ifdef CR_DEBUG
void print_tree(CRuleNodePtr);
#endif
#endif

/* error messages */
char *crule_errstr[] = {
  "Unknown error",              /* NOERR? - for completeness */
  "Unexpected token",           /* UNEXPCTTOK */
  "Unknown token",              /* UNKNWTOK */
  "And expr expected",          /* EXPCTAND */
  "Or expr expected",           /* EXPCTOR */
  "Primary expected",           /* EXPCTPRIM */
  "( expected",                 /* EXPCTOPEN */
  ") expected",                 /* EXPCTCLOSE */
  "Unknown function",           /* UNKNWFUNC */
  "Argument mismatch"           /* ARGMISMAT */
};

/* function table - null terminated */
struct crule_funclistent {
  char name[15];                /* MAXIMUM FUNCTION NAME LENGTH IS 14 CHARS!! */
  int reqnumargs;
  crule_funcptr funcptr;
};

struct crule_funclistent crule_funclist[] = {
  /* maximum function name length is 14 chars */
  {"connected", 1, crule_connected},
  {"directcon", 1, crule_directcon},
  {"via", 2, crule_via},
  {"directop", 0, crule_directop},
  {"", 0, NULL}                 /* this must be here to mark end of list */
};

#if !defined(CR_DEBUG) && !defined(CR_CHKCONF)
static int crule_connected(int numargs, void *crulearg[])
{
  struct Client *acptr;

  /* taken from m_links */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
  {
    if (!IsServer(acptr) && !IsMe(acptr))
      continue;
    if (match((char *)crulearg[0], cli_name(acptr)))
      continue;
    return (1);
  }
  return (0);
}
#else
static int crule_connected(int numargs, void **crulearg)
{
  return (0);
}
#endif

#if !defined(CR_DEBUG) && !defined(CR_CHKCONF)
static int crule_directcon(int numargs, void *crulearg[])
{
  int i;
  struct Client *acptr;

  /* adapted from m_trace and exit_one_client */
  for (i = 0; i <= HighestFd; i++)
  {
    if (!(acptr = LocalClientArray[i]) || !IsServer(acptr))
      continue;
    if (match((char *)crulearg[0], cli_name(acptr)))
      continue;
    return (1);
  }
  return (0);
}
#else
static int crule_directcon(int numargs, void **crulearg)
{
  return (0);
}
#endif

#if !defined(CR_DEBUG) && !defined(CR_CHKCONF)
static int crule_via(int numargs, void *crulearg[])
{
  struct Client *acptr;

  /* adapted from m_links */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
  {
    if (!IsServer(acptr) && !IsMe(acptr))
      continue;
    if (match((char *)crulearg[1], cli_name(acptr)))
      continue;
    if (match((char *)crulearg[0],
	      cli_name(LocalClientArray[cli_fd(cli_from(acptr))])))
      continue;
    return (1);
  }
  return (0);
}
#else
static int crule_via(int numargs, void **crulearg)
{
  return (0);
}
#endif

static int crule_directop(int numargs, void **crulearg)
{
#if !defined(CR_DEBUG) && !defined(CR_CHKCONF)
  int i;
  struct Client *acptr;

  /* adapted from m_trace */
  for (i = 0; i <= HighestFd; i++)
  {
    if (!(acptr = LocalClientArray[i]) || !IsAnOper(acptr))
      continue;
    return (1);
  }
#endif
  return (0);
}

static int crule__andor(int numargs, void *crulearg[])
{
  int result1;

  result1 = ((CRuleNodePtr) crulearg[0])->funcptr
      (((CRuleNodePtr) crulearg[0])->numargs,
      ((CRuleNodePtr) crulearg[0])->arg);
  if (crulearg[2])              /* or */
    return (result1 ||
        ((CRuleNodePtr) crulearg[1])->funcptr
        (((CRuleNodePtr) crulearg[1])->numargs,
        ((CRuleNodePtr) crulearg[1])->arg));
  else
    return (result1 &&
        ((CRuleNodePtr) crulearg[1])->funcptr
        (((CRuleNodePtr) crulearg[1])->numargs,
        ((CRuleNodePtr) crulearg[1])->arg));
}

static int crule__not(int numargs, void *crulearg[])
{
  return (!((CRuleNodePtr) crulearg[0])->funcptr
      (((CRuleNodePtr) crulearg[0])->numargs,
      ((CRuleNodePtr) crulearg[0])->arg));
}

#if !defined(CR_DEBUG) && !defined(CR_CHKCONF)
int crule_eval(struct CRuleNode* rule)
{
  return (rule->funcptr(rule->numargs, rule->arg));
}
#endif

static int crule_gettoken(int* next_tokp, const char** ruleptr)
{
  char pending = '\0';

  *next_tokp = CR_UNKNOWN;
  while (*next_tokp == CR_UNKNOWN)
    switch (*(*ruleptr)++)
    {
      case ' ':
      case '\t':
        break;
      case '&':
        if (pending == '\0')
          pending = '&';
        else if (pending == '&')
          *next_tokp = CR_AND;
        else
          return (CR_UNKNWTOK);
        break;
      case '|':
        if (pending == '\0')
          pending = '|';
        else if (pending == '|')
          *next_tokp = CR_OR;
        else
          return (CR_UNKNWTOK);
        break;
      case '!':
        *next_tokp = CR_NOT;
        break;
      case '(':
        *next_tokp = CR_OPENPAREN;
        break;
      case ')':
        *next_tokp = CR_CLOSEPAREN;
        break;
      case ',':
        *next_tokp = CR_COMMA;
        break;
      case '\0':
        (*ruleptr)--;
        *next_tokp = CR_END;
        break;
      case ':':
        *next_tokp = CR_END;
        break;
      default:
        if ((IsAlpha(*(--(*ruleptr)))) || (**ruleptr == '*') ||
            (**ruleptr == '?') || (**ruleptr == '.') || (**ruleptr == '-'))
          *next_tokp = CR_WORD;
        else
          return (CR_UNKNWTOK);
        break;
    }
  return CR_NOERR;
}

static void crule_getword(char* word, int* wordlenp, size_t maxlen, const char** ruleptr)
{
  char *word_ptr;

  word_ptr = word;
  while ((size_t)(word_ptr - word) < maxlen
      && (IsAlnum(**ruleptr)
      || **ruleptr == '*' || **ruleptr == '?'
      || **ruleptr == '.' || **ruleptr == '-'))
    *word_ptr++ = *(*ruleptr)++;
  *word_ptr = '\0';
  *wordlenp = word_ptr - word;
}

/*
 * Grammar
 *   rule:
 *     orexpr END          END is end of input or :
 *   orexpr:
 *     andexpr
 *     andexpr || orexpr
 *   andexpr:
 *     primary
 *     primary && andexpr
 *  primary:
 *    function
 *    ! primary
 *    ( orexpr )
 *  function:
 *    word ( )             word is alphanumeric string, first character
 *    word ( arglist )       must be a letter
 *  arglist:
 *    word
 *    word , arglist
 */
struct CRuleNode* crule_parse(const char *rule)
{
  const char* ruleptr = rule;
  int next_tok;
  struct CRuleNode* ruleroot = 0;
  int errcode = CR_NOERR;

  if ((errcode = crule_gettoken(&next_tok, &ruleptr)) == CR_NOERR) {
    if ((errcode = crule_parseorexpr(&ruleroot, &next_tok, &ruleptr)) == CR_NOERR) {
      if (ruleroot != NULL) {
        if (next_tok == CR_END)
          return (ruleroot);
        else
          errcode = CR_UNEXPCTTOK;
      }
      else
        errcode = CR_EXPCTOR;
    }
  }
  if (ruleroot != NULL)
    crule_free(&ruleroot);
#if !defined(CR_DEBUG) && !defined(CR_CHKCONF)
  Debug((DEBUG_ERROR, "%s in rule: %s", crule_errstr[errcode], rule));
#else
  fprintf(stderr, "%s in rule: %s\n", crule_errstr[errcode], rule);
#endif
  return 0;
}

static int crule_parseorexpr(CRuleNodePtr * orrootp, int *next_tokp, const char** ruleptr)
{
  int errcode = CR_NOERR;
  CRuleNodePtr andexpr;
  CRuleNodePtr orptr;

  *orrootp = NULL;
  while (errcode == CR_NOERR)
  {
    errcode = crule_parseandexpr(&andexpr, next_tokp, ruleptr);
    if ((errcode == CR_NOERR) && (*next_tokp == CR_OR))
    {
      orptr = (CRuleNodePtr) MyMalloc(sizeof(struct CRuleNode));
#ifdef CR_DEBUG
      fprintf(stderr, "allocating or element at %ld\n", orptr);
#endif
      orptr->funcptr = crule__andor;
      orptr->numargs = 3;
      orptr->arg[2] = (void *)1;
      if (*orrootp != NULL)
      {
        (*orrootp)->arg[1] = andexpr;
        orptr->arg[0] = *orrootp;
      }
      else
        orptr->arg[0] = andexpr;
      *orrootp = orptr;
    }
    else
    {
      if (*orrootp != NULL)
      {
        if (andexpr != NULL)
        {
          (*orrootp)->arg[1] = andexpr;
          return (errcode);
        }
        else
        {
          (*orrootp)->arg[1] = NULL;    /* so free doesn't seg fault */
          return (CR_EXPCTAND);
        }
      }
      else
      {
        *orrootp = andexpr;
        return (errcode);
      }
    }
    if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
      return (errcode);
  }
  return (errcode);
}

static int crule_parseandexpr(CRuleNodePtr * androotp, int *next_tokp, const char** ruleptr)
{
  int errcode = CR_NOERR;
  CRuleNodePtr primary;
  CRuleNodePtr andptr;

  *androotp = NULL;
  while (errcode == CR_NOERR)
  {
    errcode = crule_parseprimary(&primary, next_tokp, ruleptr);
    if ((errcode == CR_NOERR) && (*next_tokp == CR_AND))
    {
      andptr = (CRuleNodePtr) MyMalloc(sizeof(struct CRuleNode));
#ifdef CR_DEBUG
      fprintf(stderr, "allocating and element at %ld\n", andptr);
#endif
      andptr->funcptr = crule__andor;
      andptr->numargs = 3;
      andptr->arg[2] = (void *)0;
      if (*androotp != NULL)
      {
        (*androotp)->arg[1] = primary;
        andptr->arg[0] = *androotp;
      }
      else
        andptr->arg[0] = primary;
      *androotp = andptr;
    }
    else
    {
      if (*androotp != NULL)
      {
        if (primary != NULL)
        {
          (*androotp)->arg[1] = primary;
          return (errcode);
        }
        else
        {
          (*androotp)->arg[1] = NULL;   /* so free doesn't seg fault */
          return (CR_EXPCTPRIM);
        }
      }
      else
      {
        *androotp = primary;
        return (errcode);
      }
    }
    if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
      return (errcode);
  }
  return (errcode);
}

static int crule_parseprimary(CRuleNodePtr* primrootp, int *next_tokp, const char** ruleptr)
{
  CRuleNodePtr *insertionp;
  int errcode = CR_NOERR;

  *primrootp = NULL;
  insertionp = primrootp;
  while (errcode == CR_NOERR)
  {
    switch (*next_tokp)
    {
      case CR_OPENPAREN:
        if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
          break;
        if ((errcode = crule_parseorexpr(insertionp, next_tokp, ruleptr)) != CR_NOERR)
          break;
        if (*insertionp == NULL)
        {
          errcode = CR_EXPCTAND;
          break;
        }
        if (*next_tokp != CR_CLOSEPAREN)
        {
          errcode = CR_EXPCTCLOSE;
          break;
        }
        errcode = crule_gettoken(next_tokp, ruleptr);
        break;
      case CR_NOT:
        *insertionp = (CRuleNodePtr) MyMalloc(sizeof(struct CRuleNode));
#ifdef CR_DEBUG
        fprintf(stderr, "allocating primary element at %ld\n", *insertionp);
#endif
        (*insertionp)->funcptr = crule__not;
        (*insertionp)->numargs = 1;
        (*insertionp)->arg[0] = NULL;
        insertionp = (CRuleNodePtr *) & ((*insertionp)->arg[0]);
        if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
          break;
        continue;
      case CR_WORD:
        errcode = crule_parsefunction(insertionp, next_tokp, ruleptr);
        break;
      default:
        if (*primrootp == NULL)
          errcode = CR_NOERR;
        else
          errcode = CR_EXPCTPRIM;
        break;
    }
    return (errcode);
  }
  return (errcode);
}

static int crule_parsefunction(CRuleNodePtr* funcrootp, int* next_tokp, const char** ruleptr)
{
  int errcode = CR_NOERR;
  char funcname[CR_MAXARGLEN];
  int namelen;
  int funcnum;

  *funcrootp = NULL;
  crule_getword(funcname, &namelen, CR_MAXARGLEN - 1, ruleptr);
  if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
    return (errcode);
  if (*next_tokp == CR_OPENPAREN)
  {
    for (funcnum = 0;; funcnum++)
    {
      if (0 == ircd_strcmp(crule_funclist[funcnum].name, funcname))
        break;
      if (crule_funclist[funcnum].name[0] == '\0')
        return (CR_UNKNWFUNC);
    }
    if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
      return (errcode);
    *funcrootp = (CRuleNodePtr) MyMalloc(sizeof(struct CRuleNode));
#ifdef CR_DEBUG
    fprintf(stderr, "allocating function element at %ld\n", *funcrootp);
#endif
    (*funcrootp)->funcptr = NULL;       /* for freeing aborted trees */
    if ((errcode =
        crule_parsearglist(*funcrootp, next_tokp, ruleptr)) != CR_NOERR)
      return (errcode);
    if (*next_tokp != CR_CLOSEPAREN)
      return (CR_EXPCTCLOSE);
    if ((crule_funclist[funcnum].reqnumargs != (*funcrootp)->numargs) &&
        (crule_funclist[funcnum].reqnumargs != -1))
      return (CR_ARGMISMAT);
    if ((errcode = crule_gettoken(next_tokp, ruleptr)) != CR_NOERR)
      return (errcode);
    (*funcrootp)->funcptr = crule_funclist[funcnum].funcptr;
    return (CR_NOERR);
  }
  else
    return (CR_EXPCTOPEN);
}

static int crule_parsearglist(CRuleNodePtr argrootp, int *next_tokp, const char** ruleptr)
{
  int errcode = CR_NOERR;
  char *argelemp = NULL;
  char currarg[CR_MAXARGLEN];
  int arglen = 0;
  char word[CR_MAXARGLEN];
  int wordlen = 0;

  argrootp->numargs = 0;
  currarg[0] = '\0';
  while (errcode == CR_NOERR)
  {
    switch (*next_tokp)
    {
      case CR_WORD:
        crule_getword(word, &wordlen, CR_MAXARGLEN - 1, ruleptr);
        if (currarg[0] != '\0')
        {
          if ((arglen + wordlen) < (CR_MAXARGLEN - 1))
          {
            strcat(currarg, " ");
            strcat(currarg, word);
            arglen += wordlen + 1;
          }
        }
        else
        {
          strcpy(currarg, word);
          arglen = wordlen;
        }
        errcode = crule_gettoken(next_tokp, ruleptr);
        break;
      default:
#if !defined(CR_DEBUG) && !defined(CR_CHKCONF)
        collapse(currarg);
#endif
        if (!BadPtr(currarg))
        {
          DupString(argelemp, currarg);
          argrootp->arg[argrootp->numargs++] = (void *)argelemp;
        }
        if (*next_tokp != CR_COMMA)
          return (CR_NOERR);
        currarg[0] = '\0';
        errcode = crule_gettoken(next_tokp, ruleptr);
        break;
    }
  }
  return (errcode);
}

/*
 * This function is recursive..  I wish I knew a nonrecursive way but
 * I dont.  anyway, recursion is fun..  :)
 * DO NOT CALL THIS FUNTION WITH A POINTER TO A NULL POINTER
 * (ie: If *elem is NULL, you're doing it wrong - seg fault)
 */
void crule_free(struct CRuleNode** elem)
{
  int arg, numargs;

  if ((*(elem))->funcptr == crule__not)
  {
    /* type conversions and ()'s are fun! ;)  here have an asprin.. */
    if ((*(elem))->arg[0] != NULL)
      crule_free((struct CRuleNode**) &((*(elem))->arg[0]));
  }
  else if ((*(elem))->funcptr == crule__andor)
  {
    crule_free((struct CRuleNode**) &((*(elem))->arg[0]));
    if ((*(elem))->arg[1] != NULL)
      crule_free((struct CRuleNode**) &((*(elem))->arg[1]));
  }
  else
  {
    numargs = (*(elem))->numargs;
    for (arg = 0; arg < numargs; arg++)
      MyFree((*(elem))->arg[arg]);
  }
#ifdef CR_DEBUG
  fprintf(stderr, "freeing element at %ld\n", *elem);
#endif
  MyFree(*elem);
  *elem = 0;
}

#ifdef CR_DEBUG
static void print_tree(CRuleNodePtr printelem)
{
  int funcnum, arg;

  if (printelem->funcptr == crule__not)
  {
    printf("!( ");
    print_tree((CRuleNodePtr) printelem->arg[0]);
    printf(") ");
  }
  else if (printelem->funcptr == crule__andor)
  {
    printf("( ");
    print_tree((CRuleNodePtr) printelem->arg[0]);
    if (printelem->arg[2])
      printf("|| ");
    else
      printf("&& ");
    print_tree((CRuleNodePtr) printelem->arg[1]);
    printf(") ");
  }
  else
  {
    for (funcnum = 0;; funcnum++)
    {
      if (printelem->funcptr == crule_funclist[funcnum].funcptr)
        break;
      if (crule_funclist[funcnum].funcptr == NULL)
        MyCoreDump;
    }
    printf("%s(", crule_funclist[funcnum].name);
    for (arg = 0; arg < printelem->numargs; arg++)
    {
      if (arg != 0)
        printf(",");
      printf("%s", (char *)printelem->arg[arg]);
    }
    printf(") ");
  }
}

#endif

#ifdef CR_DEBUG
int main(void)
{
  char indata[256];
  CRuleNode* rule;

  printf("rule: ");
  while (fgets(indata, 256, stdin) != NULL)
  {
    indata[strlen(indata) - 1] = '\0';  /* lose the newline */
    if ((rule = crule_parse(indata)) != NULL)
    {
      printf("equivalent rule: ");
      print_tree((CRuleNodePtr) rule);
      printf("\n");
      crule_free(&rule);
    }
    printf("\nrule: ");
  }
  printf("\n");

  return 0;
}

#endif
