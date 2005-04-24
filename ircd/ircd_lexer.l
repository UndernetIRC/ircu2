/*
 * ircd_lexer.l: A lexical scanner for ircd config files.
 * This is part of ircu, an Internet Relay Chat server.
 * The contents of this file are Copyright(C) 2001 by Andrew Miller, the
 * ircd-hybrid team and the ircu team.
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
 *  USA.
 * $Id$
 */

%{
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "config.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_string.h"
#include "s_debug.h"
#include "y.tab.h"

extern int lineno;

static struct lexer_token {
  const char *string;
  int value;
} tokens[] = {
#define TOKEN(NAME) { #NAME, NAME }
  TOKEN(ADMIN),
  TOKEN(GENERAL),
  TOKEN(LOCATION),
  TOKEN(CONTACT),
  TOKEN(CLASS),
  TOKEN(PINGFREQ),
  TOKEN(CONNECT),
  TOKEN(CONNECTFREQ),
  TOKEN(MAXLINKS),
  TOKEN(MAXHOPS),
  TOKEN(SENDQ),
  TOKEN(NAME),
  TOKEN(HOST),
  TOKEN(IP),
  TOKEN(USERNAME),
  TOKEN(PASS),
  TOKEN(SECONDS),
  TOKEN(MINUTES),
  TOKEN(HOURS),
  TOKEN(DAYS),
  TOKEN(WEEKS),
  TOKEN(MONTHS),
  TOKEN(YEARS),
  TOKEN(DECADES),
  TOKEN(BYTES),
  TOKEN(KBYTES),
  TOKEN(MBYTES),
  TOKEN(GBYTES),
  TOKEN(TBYTES),
  TOKEN(PORT),
  TOKEN(SERVER),
  TOKEN(YES),
  TOKEN(NO),
  TOKEN(HUB),
  TOKEN(LEAF),
  TOKEN(UWORLD),
  TOKEN(OPER),
  TOKEN(LOCAL),
  TOKEN(VHOST),
  TOKEN(MASK),
  TOKEN(HIDDEN),
  TOKEN(MOTD),
  TOKEN(NUMERIC),
  TOKEN(NICK),
  TOKEN(JUPE),
  TOKEN(DESCRIPTION),
  TOKEN(CLIENT),
  TOKEN(REAL),
  TOKEN(REASON),
  TOKEN(RULE),
  TOKEN(ALL),
  TOKEN(CRULE),
  TOKEN(KILL),
  TOKEN(QUARANTINE),
  TOKEN(IAUTH),
  TOKEN(TIMEOUT),
  TOKEN(FEATURES),
  TOKEN(CHANNEL),
  TOKEN(PSEUDO),
  TOKEN(PREPEND),
  TOKEN(USERMODE),
  TOKEN(FAST),
#undef TOKEN
  { "administrator", ADMIN },
  { "apass_opmode", TPRIV_APASS_OPMODE },
  { "b", BYTES },
  { "badchan", TPRIV_BADCHAN },
  { "chan_limit", TPRIV_CHAN_LIMIT },
  { "deop_lchan", TPRIV_DEOP_LCHAN },
  { "die", TPRIV_DIE },
  { "display", TPRIV_DISPLAY },
  { "file", TFILE },
  { "force_local_opmode", TPRIV_FORCE_LOCAL_OPMODE },
  { "force_opmode", TPRIV_FORCE_OPMODE },
  { "gline", TPRIV_GLINE },
  { "kb", KBYTES },
  { "kilobytes", KBYTES },
  { "local_badchan", TPRIV_LOCAL_BADCHAN },
  { "local_gline", TPRIV_LOCAL_GLINE },
  { "local_jupe", TPRIV_LOCAL_JUPE },
  { "local_kill", TPRIV_LOCAL_KILL },
  { "local_opmode", TPRIV_LOCAL_OPMODE },
  { "mb", MBYTES },
  { "megabytes", MBYTES },
  { "mode_lchan", TPRIV_MODE_LCHAN },
  { "gb", GBYTES },
  { "gigabytes", GBYTES },
  { "operator", OPER },
  { "opmode", TPRIV_OPMODE },
  { "password", PASS },
  { "propagate", TPRIV_PROPAGATE },
  { "realname", REAL },
  { "rehash", TPRIV_REHASH },
  { "restart", TPRIV_RESTART },
  { "see_chan", TPRIV_SEE_CHAN },
  { "see_opers", TPRIV_SEE_OPERS },
  { "set", TPRIV_SET },
  { "show_all_invis", TPRIV_SHOW_ALL_INVIS },
  { "show_invis", TPRIV_SHOW_INVIS },
  { "tb", TBYTES },
  { "terabytes", TBYTES },
  { "unlimit_query", TPRIV_UNLIMIT_QUERY },
  { "walk_lchan", TPRIV_WALK_LCHAN },
  { "wide_gline", TPRIV_WIDE_GLINE },
  { "whox", TPRIV_WHOX },
  { NULL, 0 }
};
static int ntokens;

static int
token_compare(const void *pa, const void *pb)
{
  const struct lexer_token *ta = pa;
  const struct lexer_token *tb = pb;
  unsigned int ii = 0;
  int res;
  while (ta->string[ii] && (ToLower(ta->string[ii]) == ToLower(tb->string[ii])))
    ii++;
  res = ToLower(tb->string[ii]) - ToLower(ta->string[ii]);
  return res;
}

static void
init_ntokens(void)
{
  for (ntokens = 0; tokens[ntokens].string; ++ntokens) ;
  qsort(tokens, ntokens, sizeof(tokens[0]), token_compare);
}

static int
find_token(char *token)
{
  struct lexer_token *tok;
  if (!ntokens)
    init_ntokens();
  tok = bsearch(&token, tokens, ntokens, sizeof(tokens[0]), token_compare);
  return tok ? tok->value : 0;
}

void
init_lexer(void)
{
  yyin = fopen(configfile, "r");
  if (yyin == NULL)
  {
#ifdef YY_FATAL_ERROR
    YY_FATAL_ERROR("Could not open the configuration file.");
#else
    fprintf(stderr, "Could not open the configuration file.");
#endif
  }
#ifdef YY_NEW_FILE
  YY_NEW_FILE;
#endif
  lineno = 1;
}

%}

WHITE [ \t\r]+
SHCOMMENT #[^\n]*
NUMBER [0-9]+
QSTRING \"[^"\n]+[\"\n]
%%

{QSTRING} {yytext[yyleng-1] = 0; DupString(yylval.text, yytext+1); return QSTRING;}
{NUMBER} {yylval.num = strtoul(yytext, NULL, 10); return NUMBER;}
{WHITE} ;
{SHCOMMENT} ;

[a-zA-Z_]+ { int res = find_token(yytext); if (res) return res; else REJECT; }
\n lineno++;
. return yytext[0];
