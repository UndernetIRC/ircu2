/*
 * IRC - Internet Relay Chat, include/common.c
 * Copyright (C) 1998 Andrea Cocito
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * TABLE GENERATOR
 * The following part of code is NOT included in the actual server's
 * or library source, it's just used to build the above tables
 *
 * This should rebuild the actual tables and automatically place them
 * into this source file, note that this part of code is for developers
 * only, it's supposed to work on both signed and unsigned chars but I
 * actually tested it only on signed-char architectures, the code and
 * macros actually used by the server instead DO work and have been tested
 * on platforms where0 char is both signed or unsigned, this is true as long
 * as the <limits.h> macros are set properly and without any need to rebuild
 * the tables (wich as said an admin should NEVER do, tables need to be rebuilt
 * only when one wants to really change the results or when one has to
 * compile on architectures where a char is NOT eight bits [?!], yes
 * it all is supposed to work in that case too... but I can't test it
 * because I've not found a machine in the world where this happes).
 *
 * NEVER -f[un]signed-char on gcc since that does NOT fix the named macros
 * and you end up in a non-ANSI environment where CHAR_MIN and CHAR_MAX
 * are _not_ the real limits of a default 'char' type. This is true for
 * both admins and coders.
 *
 */
#include "config.h"

#include "ircd_chattr.h"
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>


static void zeroTables(void);
static void markString(int macro, const char *s);
static void unMarkString(int macro, const char *s);
static void markRange(int macro, char from, char to);
static void moveMacro(int from, int to);
static void setLowHi(const char firstlow, const char lastlow,
    const char firsthi);

char NTL_tolower_tab[1 + CHAR_MAX - CHAR_MIN];	/* 256 bytes */
char NTL_toupper_tab[1 + CHAR_MAX - CHAR_MIN];	/* 256 bytes */
int NTL_char_attrib[1 + CHAR_MAX - CHAR_MIN];	/* 256 ints = 0.5 to 2 kilobytes */

/*
 * makeTables() 
 * Where we make the tables, edit ONLY this to change the tables.
 */

static void makeTables(void)
{

  /* Start from a known status */
  zeroTables();

  /* Make the very elementary sets */
  markRange(NTL_LOWER, 'a', 'z');
  markString(NTL_LOWER, "{|}~");

  markRange(NTL_UPPER, 'A', 'Z');
  markString(NTL_UPPER, "[\\]^");

  markRange(NTL_DIGIT, '0', '9');

  markRange(NTL_CNTRL, '\000', '\037');

  markString(NTL_PUNCT, "!\"#$%&'()*+,-./:;<=>?@_`");

  markString(NTL_SPACE, "\011\012\013\014\015\040");

  /* Make the derived sets, 
   * WARNING: The order of these calls is important, some depend on 
   * the results of the previous ones ! */

  moveMacro(NTL_LOWER | NTL_UPPER, NTL_ALPHA);
  moveMacro(NTL_ALPHA | NTL_DIGIT, NTL_ALNUM);
  moveMacro(NTL_ALNUM | NTL_PUNCT, NTL_GRAPH);

  moveMacro(NTL_GRAPH, NTL_PRINT);
  markString(NTL_PRINT, " ");

  markRange(NTL_IRCCH, 0, (char) UCHAR_MAX);
  unMarkString(NTL_IRCCH, "\007\040\054\240");

  markRange(NTL_IRCCL, '\300', '\326');
  markRange(NTL_IRCCL, '\330', '\336');

  moveMacro(NTL_ALNUM, NTL_IRCHN);
  markString(NTL_IRCHN, "-_.");	/* Some DNS might allow '_' per RFC 1033 ! */

  moveMacro(NTL_DIGIT, NTL_IRCIP);
  markString(NTL_IRCIP, ".");

  moveMacro(NTL_DIGIT | NTL_ALPHA, NTL_IRCNK);
  markString(NTL_IRCNK, "-_`");

  moveMacro(NTL_ALNUM, NTL_IRCUI);
  markRange(NTL_IRCUI, '\xe0', '\xf6');
  markRange(NTL_IRCUI, '\xf8', '\xfe');
  markRange(NTL_IRCUI, '\xc0', '\xd6');
  markRange(NTL_IRCUI, '\xd8', '\xde');
  markString(NTL_IRCUI, ".-_^'`~");
  markString(NTL_EOL, "\n\r");
  markString(NTL_CHPFX, "#&");
  markString(NTL_KTIME, " ,-0123456789");

  /* And finally let's take care of the toLower/toUpper stuff */

  setLowHi('a', 'z', 'A');
  setLowHi('\xe0', '\xf6', '\xc0');
  setLowHi('\xf8', '\xfe', '\xd8');
  setLowHi('{', '~', '[');
}

/* 
 * main()
 * This is the main program to be executed for -DMAKETABLES
 */

static void dumphw(int *p, int beg);
static void dumphb(char *p, int beg);

int main(void)
{
  int i;

  /* Make the tables */
  makeTables();

  /* Dump them as ANSI C source to be included below */
  printf("/*\n * Automatically Generated Tables - DO NOT EDIT\n */\n");
  printf("#include <limits.h>\n");

  /* NTL_tolower_tab */
  printf("const char ToLowerTab_8859_1[] = {\n");
  printf("#if (CHAR_MIN<0)\n");
  i = (int)((char)SCHAR_MIN);
  dumphb(NTL_tolower_tab, i);
  printf("                ,\n");
  printf("#endif /* (CHAR_MIN<0) */\n");
  i = 0;
  dumphb(NTL_tolower_tab, i);
  printf("#if (!(CHAR_MIN<0))\n");
  printf("                ,\n");
  i = (int)((char)SCHAR_MIN);
  dumphb(NTL_tolower_tab, i);
  printf("#endif /* (!(CHAR_MIN<0)) */\n");
  printf("  };\n\n");

  /* NTL_toupper_tab */
  printf("const char ToUpperTab_8859_1[] = {\n");
  printf("#if (CHAR_MIN<0)\n");
  i = (int)((char)SCHAR_MIN);
  dumphb(NTL_toupper_tab, i);
  printf("                ,\n");
  printf("#endif /* (CHAR_MIN<0) */\n");
  i = 0;
  dumphb(NTL_toupper_tab, i);
  printf("#if (!(CHAR_MIN<0))\n");
  printf("                ,\n");
  i = (int)((char)SCHAR_MIN);
  dumphb(NTL_toupper_tab, i);
  printf("#endif /* (!(CHAR_MIN<0)) */\n");
  printf("  };\n\n");

  /* NTL_char_attrib */
  printf("const unsigned int IRCD_CharAttrTab[] = {\n");
  printf("#if (CHAR_MIN<0)\n");
  i = (int)((char)SCHAR_MIN);
  dumphw(NTL_char_attrib, i);
  printf("                ,\n");
  printf("#endif /* (CHAR_MIN<0) */\n");
  i = 0;
  dumphw(NTL_char_attrib, i);
  printf("#if (!(CHAR_MIN<0))\n");
  printf("                ,\n");
  i = (int)((char)SCHAR_MIN);
  dumphw(NTL_char_attrib, i);
  printf("#endif /* (!(CHAR_MIN<0)) */\n");
  printf("  };\n\n");

  return 0;

}

/* A few utility functions for makeTables() */

static void zeroTables(void)
{
  int i;
  for (i = CHAR_MIN; i <= CHAR_MAX; i++)
  {
    NTL_tolower_tab[i - CHAR_MIN] = (char)i;	/* Unchanged */
    NTL_toupper_tab[i - CHAR_MIN] = (char)i;	/* Unchanged */
    NTL_char_attrib[i - CHAR_MIN] = 0x0000;	/* Nothing */
  }
}

static void markString(int macro, const char *s)
{
  while (*s)
    NTL_char_attrib[*(s++) - CHAR_MIN] |= macro;
}

static void unMarkString(int macro, const char *s)
{
  while (*s)
    NTL_char_attrib[*(s++) - CHAR_MIN] &= ~macro;
}

static void markRange(int macro, char from, char to)
{
  int i;
  for (i = CHAR_MIN; i <= CHAR_MAX; i++)
    if (((unsigned char)i >= (unsigned char)from)
	&& ((unsigned char)i <= (unsigned char)to))
      NTL_char_attrib[(char)i - CHAR_MIN] |= macro;
}

static void moveMacro(int from, int to)
{
  int i;
  for (i = CHAR_MIN; i <= CHAR_MAX; i++)
    if (NTL_char_attrib[i - CHAR_MIN] & from)
      NTL_char_attrib[i - CHAR_MIN] |= to;
}

static void setLowHi(const char firstlow, const char lastlow,
    const char firsthi)
{
  int i, j;
  for (i = CHAR_MIN; i <= CHAR_MAX; i++)
    if (((unsigned char)i >= (unsigned char)firstlow)
	&& ((unsigned char)i <= (unsigned char)lastlow))
    {
      j = ((int)((char)(i + (int)(firsthi - firstlow))));
      NTL_tolower_tab[((char)j) - CHAR_MIN] = (char)i;
      NTL_toupper_tab[((char)i) - CHAR_MIN] = (char)j;
    }
}

/* These are used in main() to actually dump the tables, each function
   dumps half table as hex/char constants... */

#define ROWSIZE 8

static void dumphb(char *tbl, int beg)
{
  int i, j, k;
  char *p = &tbl[beg - CHAR_MIN];
  char c;
  for (i = 0; i <= SCHAR_MAX; i += ROWSIZE)
  {
    k = i + ROWSIZE - 1;
    if (k > SCHAR_MAX)
      k = SCHAR_MAX;

    c = (char)(beg + i);
    printf("/*");
    if ((c > 0) && (c < SCHAR_MAX) && (isprint(c)) && (c != '\\')
	&& (c != '\''))
      printf(" '%c'", c);
    else
      printf(" x%02x", ((int)((unsigned char)c)));

    c = (char)(beg + k);
    printf("-");
    if ((c > 0) && (c < SCHAR_MAX) && (isprint(c)) && (c != '\\')
	&& (c != '\''))
      printf("'%c'", c);
    else
      printf("x%02x", ((int)((unsigned char)c)));
    printf(" */");

    for (j = i; j <= k; j++)
    {
      c = p[j];
      if ((c > 0) && (c < SCHAR_MAX) && (isprint(c)) && (c != '\\')
	  && (c != '\''))
	printf("    '%c'", c);
      else
	printf(" '\\x%02x'", ((int)((unsigned char)c)));
      if (j < SCHAR_MAX)
	printf(",");
    }
    printf("\n");
  }
}

static void dumphw(int *tbl, int beg)
{
  int i, j, k;
  int *p = &tbl[beg - CHAR_MIN];
  char c;
  for (i = 0; i <= SCHAR_MAX; i += ROWSIZE)
  {
    k = i + ROWSIZE - 1;
    if (k > SCHAR_MAX)
      k = SCHAR_MAX;

    c = (char)(beg + i);
    printf("/*");
    if ((c > 0) && (c < SCHAR_MAX) && (isprint(c)) && (c != '\\')
	&& (c != '\''))
      printf(" '%c'", c);
    else
      printf(" x%02x", ((int)((unsigned char)c)));

    c = (char)(beg + k);
    printf("-");
    if ((c > 0) && (c < SCHAR_MAX) && (isprint(c)) && (c != '\\')
	&& (c != '\''))
      printf("'%c'", c);
    else
      printf("x%02x", ((int)((unsigned char)c)));
    printf(" */");

    for (j = i; j <= k; j++)
    {
      printf(" 0x%04x", p[j] & 0xffffffff);
      if (j < SCHAR_MAX)
	printf(",");
    }
    printf("\n");
  }
}

