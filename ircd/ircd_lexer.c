#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "ircd.h"  /* configfile */
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_string.h" /* ircd_strcmp() */
#include "s_conf.h"
#include "y.tab.h"

#if !defined(O_CLOEXEC)
# define O_CLOEXEC O_RDONLY
#endif

/* NOTE: This file uses <ctype.h> and isalnum() rather than ircd_chattr.h
 * and IsAlnum() because IsAlnum() returns true for "{|}~[\\]^".
 */

/** Represents one config file. */
struct lex_file
{
  /** Config file that included this one. */
  struct lex_file *parent;

  /** Name of this config file. */
  char *name;

  /** Bitmask of allowed config blocks for this file. */
  unsigned int allowed;

  /** File descriptor for this config file. */
  int fd;

  /** Current line number in this config file. */
  int lineno;

  /** Offset in #buf of the token we are looking at.
   * When yyinput() is not running, this is just past the end of the
   * last token, and may be equal to #buf_used.
   */
  int tok_ofs;

  /** Number of bytes currently valid in #buf. */
  int buf_used;

  /** Current buffer of input from the file. */
  char buf[1024];
};

struct lexer_token {
  const char *string;
  int value;
};

/* WARNING: tokens MUST be lower case and lexicographically sorted */
static const struct lexer_token tokens[] = {
  { "admin", ADMIN },
  { "administrator", ADMIN },
  { "all", ALL },
  { "apass_opmode", TPRIV_APASS_OPMODE },
  { "auto", AUTOCONNECT },
  { "autoconnect", AUTOCONNECT },
  { "b", BYTES },
  { "badchan", TPRIV_BADCHAN },
  { "bytes", BYTES },
  { "chan_limit", TPRIV_CHAN_LIMIT },
  { "class", CLASS },
  { "client", CLIENT },
  { "connect", CONNECT },
  { "connectfreq", CONNECTFREQ },
  { "contact", CONTACT },
  { "crule", CRULE },
  { "days", DAYS },
  { "decades", DECADES },
  { "deop_lchan", TPRIV_DEOP_LCHAN },
  { "description", DESCRIPTION },
  { "die", TPRIV_DIE },
  { "display", TPRIV_DISPLAY },
  { "dns", DNS },
  { "except", EXCEPT },
  { "fast", FAST },
  { "features", FEATURES },
  { "file", TFILE },
  { "force_local_opmode", TPRIV_FORCE_LOCAL_OPMODE },
  { "force_opmode", TPRIV_FORCE_OPMODE },
  { "gb", GBYTES },
  { "gbytes", GBYTES },
  { "general", GENERAL },
  { "gigabytes", GBYTES },
  { "gline", TPRIV_GLINE },
  { "hidden", HIDDEN },
  { "host", HOST },
  { "hours", HOURS },
  { "hub", HUB },
  { "iauth", IAUTH },
  { "include", INCLUDE },
  { "ip", IP },
  { "ipcheck", IPCHECK },
  { "ipv4", TOK_IPV4 },
  { "ipv6", TOK_IPV6 },
  { "jupe", JUPE },
  { "kb", KBYTES },
  { "kbytes", KBYTES },
  { "kill", KILL },
  { "kilobytes", KBYTES },
  { "leaf", LEAF },
  { "list_chan", TPRIV_LIST_CHAN },
  { "local", LOCAL },
  { "local_badchan", TPRIV_LOCAL_BADCHAN },
  { "local_gline", TPRIV_LOCAL_GLINE },
  { "local_jupe", TPRIV_LOCAL_JUPE },
  { "local_kill", TPRIV_LOCAL_KILL },
  { "local_opmode", TPRIV_LOCAL_OPMODE },
  { "location", LOCATION },
  { "mask", MASK },
  { "maxhops", MAXHOPS },
  { "maxlinks", MAXLINKS },
  { "mb", MBYTES },
  { "mbytes", MBYTES },
  { "megabytes", MBYTES },
  { "minutes", MINUTES },
  { "mode_lchan", TPRIV_MODE_LCHAN },
  { "months", MONTHS },
  { "motd", MOTD },
  { "name", NAME },
  { "nick", NICK },
  { "no", NO },
  { "numeric", NUMERIC },
  { "oper", OPER },
  { "operator", OPER },
  { "opmode", TPRIV_OPMODE },
  { "pass", PASS },
  { "password", PASS },
  { "pingfreq", PINGFREQ },
  { "port", PORT },
  { "prepend", PREPEND },
  { "program", PROGRAM },
  { "propagate", TPRIV_PROPAGATE },
  { "pseudo", PSEUDO },
  { "quarantine", QUARANTINE },
  { "real", REAL },
  { "realname", REAL },
  { "reason", REASON },
  { "rehash", TPRIV_REHASH },
  { "restart", TPRIV_RESTART },
  { "rule", RULE },
  { "seconds", SECONDS },
  { "see_chan", TPRIV_SEE_CHAN },
  { "see_opers", TPRIV_SEE_OPERS },
  { "sendq", SENDQ },
  { "server", SERVER },
  { "set", TPRIV_SET },
  { "show_all_invis", TPRIV_SHOW_ALL_INVIS },
  { "show_invis", TPRIV_SHOW_INVIS },
  { "tb", TBYTES },
  { "tbytes", TBYTES },
  { "terabytes", TBYTES },
  { "unlimit_query", TPRIV_UNLIMIT_QUERY },
  { "usermode", USERMODE },
  { "username", USERNAME },
  { "uworld", UWORLD },
  { "vhost", VHOST },
  { "walk_lchan", TPRIV_WALK_LCHAN },
  { "webirc", WEBIRC },
  { "weeks", WEEKS },
  { "whox", TPRIV_WHOX },
  { "wide_gline", TPRIV_WIDE_GLINE },
  { "years", YEARS },
  { "yes", YES },
  { NULL, 0 }
};
static const int ntokens = sizeof(tokens) / sizeof(tokens[0]) - 1;
static struct lex_file *yy_in;

int lexer_allowed(unsigned int bitnum)
{
  return !yy_in || ((yy_in->allowed & (1u << bitnum)) != 0);
}

const char *lexer_position(int *lineno)
{
  if (yy_in)
  {
    if (lineno)
      *lineno = yy_in->lineno;
    return yy_in->name;
  }

  if (lineno)
    *lineno = -1;
  return "<undef>";
}

static int lexer_open(const char *fname, int allow_fail, unsigned int allowed)
{
  struct lex_file *obj;

  obj = MyMalloc(sizeof(*obj));
  obj->fd = open(fname, O_RDONLY | O_NOCTTY | O_CLOEXEC);
  DupString(obj->name, fname);
  obj->allowed = allowed;
  obj->parent = yy_in;
  obj->lineno = 1;
  obj->tok_ofs = obj->buf_used = 0;
  yy_in = obj;

  if (obj->fd < 0) {
    yyerror("error opening file");
    if (!allow_fail) {
      yy_in = obj->parent;
      MyFree(obj);
      return -1;
    }
  }

  return 0;
}

static void lexer_pop(void)
{
  struct lex_file *obj;

  obj = yy_in;
  yy_in = obj->parent;
  close(obj->fd);
  MyFree(obj->name);
  MyFree(obj);		
}

int init_lexer(void)
{
#if !defined(NDEBUG)
  int ii, jj;

  assert(!yy_in);

  for (ii = 0; ii < ntokens; ++ii) {
    char ch;

    for (jj = 0; (ch = tokens[ii].string[jj]) != '\0'; ++jj) {
      if (!islower(ch) && !isdigit(ch) && ch != '_') {
        log_write(LS_CONFIG, L_CRIT, 0, "token %s is not lower case",
          tokens[ii].string);
      }
    }

    if (ii > 0 && ircd_strcmp(tokens[ii-1].string, tokens[ii].string) >= 0) {
      log_write(LS_CONFIG, L_CRIT, 0, "token ordering error: %s >= %s",
        tokens[ii-1].string, tokens[ii].string);
    }
  }
#endif

  return lexer_open(configfile, 1, ~0u) == 0; /* we return non-zero on success */
}

void deinit_lexer(void)
{
  assert(!yy_in);

  while (yy_in) {
    lexer_pop();
  }
}

void lexer_include(const char *fname, unsigned int allowed)
{
  lexer_open(fname, 1, allowed);
}

static int token_compare(const void *key, const void *ptok)
{
  const char *word = key;
  const struct lexer_token *tok = ptok;
  unsigned int ii = 0;
  while (word[ii] && (tolower(word[ii]) == tok->string[ii]))
    ii++;
  return tolower(word[ii]) - tok->string[ii];
}

static int find_token(char *token)
{
  struct lexer_token *tok;
  tok = bsearch(token, tokens, ntokens, sizeof(tokens[0]), token_compare);
  return tok ? tok->value : 0;
}

int yylex(void)
{
  char *pos, *stop, *start;
  ssize_t nbr;
  char save;

#if !defined(YYEOF)
# define YYEOF 0
#endif
  if (!yy_in)
    return YYEOF;

  if (yy_in->fd < 0)
    return TOKERR;

  for (;;) {
    pos = yy_in->buf + yy_in->tok_ofs;
    stop = yy_in->buf + yy_in->buf_used;

    /* Skip whitespace at the start of the buffer. */
    while ((pos < stop) && isspace(*pos)) {
      if (*pos++ == '\n')
        ++yy_in->lineno;
    }
    yy_in->tok_ofs = pos - yy_in->buf;

    /* If we are looking at a comment, chomp through EOL. */
    if ((pos < stop) && (*pos == '#')) {
      while ((++pos < stop) && (*pos != '\n')) {}
      if (pos == stop)
        goto grab_more;
      yy_in->tok_ofs = ++pos - yy_in->buf;
      ++yy_in->lineno;
      continue;
    }

    /* Are we looking at a quoted string? */
    if ((pos < stop) && (*pos == '"')) {
      start = pos;
      while ((++pos < stop) && (*pos != '\n') && (*pos != '"')) {}
      if (pos == stop)
        goto grab_more;
      if (*pos == '\n') {
        log_write(LS_CONFIG, L_CRIT, 0, "newline in quoted string at line %d of %s",
          yy_in->lineno, yy_in->name);
      }
      *pos++ = '\0';
      DupString(yylval.text, start + 1);
      yy_in->tok_ofs = pos - yy_in->buf;
      return QSTRING;
    }

    /* Are we looking at a number? */
    if ((pos < stop) && isdigit(*pos)) {
      int num = 0;
      do {
        num = (num * 10) + *pos - '0';
      } while ((++pos < stop) && isdigit(*pos));
      if (pos == stop)
        goto grab_more;
      yy_in->tok_ofs = pos - yy_in->buf;
      yylval.num = num;
      return NUMBER;
    }

    /* Are we looking at a bare token? */
    if ((pos < stop) && isalpha(*pos)) {
      start = pos;
      while ((++pos < stop) && (isalnum(*pos) || *pos == '_')) {}
      if (pos == stop)
        goto grab_more;
      save = *pos;
      *pos = '\0';
      nbr = find_token(start);
      *pos = save;
      yy_in->tok_ofs = pos - yy_in->buf;
      if (nbr)
        return nbr;
      log_write(LS_CONFIG, L_CRIT, 0, "unhandled token %s at line %d of %s",
        start, yy_in->lineno, yy_in->name);
    }

    /* Otherwise we are looking at a meaningful character. */
    if (pos < stop) {
      yy_in->tok_ofs = ++pos - yy_in->buf;
      return pos[-1];
    }

  grab_more:
    /* Shift the live part of the buffer to the start. */
    if (yy_in->tok_ofs > 0) {
      assert(yy_in->tok_ofs <= yy_in->buf_used);
      yy_in->buf_used -= yy_in->tok_ofs;
      memmove(yy_in->buf, yy_in->buf + yy_in->tok_ofs, yy_in->buf_used);
      yy_in->tok_ofs = 0;
    }

    /* Do we have space to read more data from disk? */
    if (yy_in->buf_used >= sizeof(yy_in->buf)) {
      log_write(LS_CONFIG, L_CRIT, 0, "token at line %d of %s too big",
        yy_in->lineno, yy_in->name);
    }

    /* Read more data into the buffer. */
    nbr = read(yy_in->fd, yy_in->buf + yy_in->buf_used,
      sizeof(yy_in->buf) - yy_in->buf_used);
    if (nbr == 0) {
      lexer_pop();
      if (!yy_in)
        return 0;
      return TEOF;
    }
    if (nbr < 0) {
      log_write(LS_CONFIG, L_ERROR, 0, "read from %s failed: %s",
        yy_in->name, strerror(errno));
      return 0;
    }
    yy_in->buf_used += nbr;
    assert(yy_in->buf_used <= sizeof(yy_in->buf));
  }
}
