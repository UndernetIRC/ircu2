/*
 * IRC - Internet Relay Chat, common/match.c
 * Copyright (C) 1990 Jarkko Oikarinen
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
/** @file
 * @brief Functions to match strings against IRC mask strings.
 * @version $Id$
 */
#include "config.h"

#include "match.h"
#include "ircd_chattr.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"

/*
 * mmatch()
 *
 * Written by Run (carlo@runaway.xs4all.nl), 25-10-96
 *
 *
 * From: Carlo Wood <carlo@runaway.xs4all.nl>
 * Message-Id: <199609021026.MAA02393@runaway.xs4all.nl>
 * Subject: [C-Com] Analysis for `mmatch' (was: gline4 problem)
 * To: coder-com@mail.undernet.org (coder committee)
 * Date: Mon, 2 Sep 1996 12:26:01 +0200 (MET DST)
 *
 * We need a new function `mmatch(const char *old_mask, const char *new_mask)'
 * which returns `true' likewise the current `match' (start with copying it),
 * but which treats '*' and '?' in `new_mask' differently (not "\*" and "\?" !)
 * as follows:  a '*' in `new_mask' does not match a '?' in `old_mask' and
 * a '?' in `new_mask' does not match a '\?' in `old_mask'.
 * And ofcourse... a '*' in `new_mask' does not match a '\*' in `old_mask'...
 * And last but not least, '\?' and '\*' in `new_mask' now become one character.
 */

/** Compares one mask against another.
 * One wildcard mask may be said to be a superset of another if the
 * set of strings matched by the first is a proper superset of the set
 * of strings matched by the second.  In practical terms, this means
 * that the second is made redundant by the first.
 *
 * The logic for this test is similar to that in match(), but a
 * backslash in old_mask only matches a backslash in new_mask (and
 * requires the next character to match exactly), and -- after
 * contiguous runs of wildcards are logically collapsed -- a '?' in
 * old_mask does not match a '*' in new_mask.
 *
 * @param[in] old_mask One wildcard mask.
 * @param[in] new_mask Another wildcard mask.
 * @return Zero if \a old_mask is a superset of \a new_mask, non-zero otherwise.
 */
int mmatch(const char *old_mask, const char *new_mask)
{
  const char *m = old_mask;
  const char *n = new_mask;
  const char *ma = m;
  const char *na = n;
  int wild = 0;
  int mq = 0, nq = 0;

  while (1)
  {
    if (*m == '*')
    {
      while (*m == '*')
        m++;
      wild = 1;
      ma = m;
      na = n;
    }

    if (!*m)
    {
      if (!*n)
        return 0;
      for (m--; (m > old_mask) && (*m == '?'); m--)
        ;
      if ((*m == '*') && (m > old_mask) && (m[-1] != '\\'))
        return 0;
      if (!wild)
        return 1;
      m = ma;

      /* Added to `mmatch' : Because '\?' and '\*' now is one character: */
      if ((*na == '\\') && ((na[1] == '*') || (na[1] == '?')))
        ++na;

      n = ++na;
    }
    else if (!*n)
    {
      while (*m == '*')
        m++;
      return (*m != 0);
    }
    if ((*m == '\\') && ((m[1] == '*') || (m[1] == '?')))
    {
      m++;
      mq = 1;
    }
    else
      mq = 0;

    /* Added to `mmatch' : Because '\?' and '\*' now is one character: */
    if ((*n == '\\') && ((n[1] == '*') || (n[1] == '?')))
    {
      n++;
      nq = 1;
    }
    else
      nq = 0;

/*
 * This `if' has been changed compared to match() to do the following:
 * Match when:
 *   old (m)         new (n)         boolean expression
 *    *               any             (*m == '*' && !mq) ||
 *    ?               any except '*'  (*m == '?' && !mq && (*n != '*' || nq)) ||
 * any except * or ?  same as m       (!((*m == '*' || *m == '?') && !mq) &&
 *                                      ToLower(*m) == ToLower(*n) &&
 *                                        !((mq && !nq) || (!mq && nq)))
 *
 * Here `any' also includes \* and \? !
 *
 * After reworking the boolean expressions, we get:
 * (Optimized to use boolean short-circuits, with most frequently occurring
 *  cases upfront (which took 2 hours!)).
 */
    if ((*m == '*' && !mq) ||
        ((!mq || nq) && ToLower(*m) == ToLower(*n)) ||
        (*m == '?' && !mq && (*n != '*' || nq)))
    {
      if (*m)
        m++;
      if (*n)
        n++;
    }
    else
    {
      if (!wild)
        return 1;
      m = ma;

      /* Added to `mmatch' : Because '\?' and '\*' now is one character: */
      if ((*na == '\\') && ((na[1] == '*') || (na[1] == '?')))
        ++na;

      n = ++na;
    }
  }
}

/*
 * Compare if a given string (name) matches the given
 * mask (which can contain wild cards: '*' - match any
 * number of chars, '?' - match any single character.
 *
 * return  0, if match
 *         1, if no match
 *
 *  Originally by Douglas A Lewis (dalewis@acsu.buffalo.edu)
 *  Rewritten by Timothy Vogelsang (netski), net@astrolink.org
 */

/** Check a string against a mask.
 * This test checks using traditional IRC wildcards only: '*' means
 * match zero or more characters of any type; '?' means match exactly
 * one character of any type.  A backslash escapes the next character
 * so that a wildcard may be matched exactly.
 * @param[in] mask Wildcard-containing mask.
 * @param[in] name String to check against \a mask.
 * @return Zero if \a mask matches \a name, non-zero if no match.
 */
int match(const char *mask, const char *name)
{
  const char *m = mask, *n = name;
  const char *m_tmp = mask, *n_tmp = name;
  int star_p;

  for (;;) switch (*m) {
  case '\0':
    if (!*n)
      return 0;
  backtrack:
    if (m_tmp == mask)
      return 1;
    m = m_tmp;
    n = ++n_tmp;
    if (*n == '\0')
      return 1;
    break;
  case '\\':
    if ((m[1] == '*') || (m[1] == '?'))
      m++;
    goto normal_character;
  case '*': case '?':
    for (star_p = 0; ; m++) {
      if (*m == '*')
        star_p = 1;
      else if (*m == '?') {
        if (!*n++)
          goto backtrack;
      } else break;
    }
    if (star_p) {
      if (!*m)
        return 0;
      m_tmp = m;
      for (n_tmp = n; *n && ToLower(*n) != ToLower(*m); n++) ;
    }
    /* and fall through */
  default:
  normal_character:
    if (!*n)
      return *m != '\0';
    if (ToLower(*m) != ToLower(*n))
      goto backtrack;
    m++;
    n++;
    break;
  }
}

/*
 * collapse()
 * Collapse a pattern string into minimal components.
 * This particular version is "in place", so that it changes the pattern
 * which is to be reduced to a "minimal" size.
 *
 * (C) Carlo Wood - 6 Oct 1998
 * Speedup rewrite by Andrea Cocito, December 1998.
 * Note that this new optimized algorithm can *only* work in place.
 */

/** Collapse a mask string to remove redundancies.
 * Specifically, it replaces a sequence of '*' followed by additional
 * '*' or '?' with the same number of '?'s as the input, followed by
 * one '*'.  This minimizes useless backtracking when matching later.
 * @param[in,out] mask Mask string to collapse.
 * @return Pointer to the start of the string.
 */
char *collapse(char *mask)
{
  int star = 0;
  char *m = mask;
  char *b;

  if (m)
  {
    do
    {
      if ((*m == '*') && ((m[1] == '*') || (m[1] == '?')))
      {
        b = m;
        do
        {
          if (*m == '*')
            star = 1;
          else
          {
            if (star && (*m != '?'))
            {
              *b++ = '*';
              star = 0;
            };
            *b++ = *m;
            if ((*m == '\\') && ((m[1] == '*') || (m[1] == '?')))
              *b++ = *++m;
          };
        }
        while (*m++);
        break;
      }
      else
      {
        if ((*m == '\\') && ((m[1] == '*') || (m[1] == '?')))
          m++;
      };
    }
    while (*m++);
  };
  return mask;
}

/*
 ***************** Nemesi's matchcomp() / matchexec() **************
 */

/** @page compiledmasks Compiled Masks
 * These functions allow the use of "compiled" masks, you compile a mask
 * by means of matchcomp() that gets the plain text mask as input and writes
 * its result in the memory locations addressed by the 3 parameters:
 * - *cmask will contain the text of the compiled mask
 * - *minlen will contain the length of the shortest string that can match 
 *   the mask
 * - *charset will contain the minimal set of chars needed to match the mask
 * You can pass NULL as *charset and it will be simply not returned, but you
 * MUST pass valid pointers for *minlen and *cmask (which must be big enough 
 * to contain the compiled mask text that is in the worst case as long as the 
 * text of the mask itself in plaintext format) and the return value of 
 * matchcomp() will be the number of chars actually written there (excluded 
 * the trailing zero). cmask can be == mask, matchcomp() can work in place.
 * The {cmask, minlen} couple of values make the real compiled mask and
 * need to be passed to the functions that use the compiled mask, if you pass
 * the wrong minlen or something wrong in cmask to one of these expect a
 * coredump. This means that when you record a compiled mask you must store
 * *both* these values.
 * Once compiled the mask can be used to match a string by means of 
 * matchexec(), it can be printed back to human-readable format by means
 * of sprintmatch() or it can be compared to another compiled mask by means
 * of mmexec() that will tell if it completely overrides that mask (a lot like
 * what mmatch() does for plain text masks).
 * You can gain a lot of speed in many situations avoiding to matchexec() when:
 * - The maximum length of the field you are about to match() the mask to is
 *   shorter than minlen, in example when matching abc*def*ghil with a nick:
 *   It just cannot match since a nick is at most 9 chars long and the mask
 *   needs at least 10 chars (10 will be the value returned in minlen).
 * - The charset allowed for the field you are about to match to doesn't
 *   "contain" the charset returned by matchcomp(), in example when you
 *   have *.* as mask it makes no sense to try to match it against a nick
 *   because, again, a nick can't contain a '.', you can check this with
 *   a simple (charset & NTL_IRCNK) in this case.
 * - As a special case, since compiled masks are forced to lowercase,
 *   it would make no sense to use the NTL_LOWER and NTL_UPPER on a compiled
 *   mask, thus they are reused as follows: if the NTL_LOWER bit of charset
 *   is set it means that the mask contains only non-wilds chars (i.e. you can
 *   use strCasecmp() to match it or a direct hash lookup), if the NTL_UPPER
 *   bit is set it means that it contains only wild chars (and you can
 *   match it with strlen(field)>=minlen).
 * Do these optimizations ONLY when the data you are about to pass to
 * matchexec() are *known* to be invalid in advance, using strChattr() 
 * or strlen() on the text would be slower than calling matchexec() directly
 * and let it fail.
 * Internally a compiled mask contain in the *cmask area the text of
 * the plain text form of the mask itself with applied the following hacks:
 * - All characters are forced to lowercase (so that uppercase letters and
 *   specifically the symbols 'A' and 'Z' are reserved for special use)
 * - All non-escaped stars '*' are replaced by the letter 'Z'
 * - All non-escaped question marks '?' are replaced by the letter 'A' 
 * - All escape characters are removed, the wilds escaped by them are
 *   then passed by without the escape since they don't collide anymore
 *   with the real wilds (encoded as A/Z) 
 * - Finally the part of the mask that follows the last asterisk is
 *   reversed (byte order mirroring) and moved right after the first
 *   asterisk.
 * After all this a mask like:   Head*CHUNK1*chu\*nK2*ch??k3*TaIl 
 *               .... becomes:   headZliatZchunk1Zchu*nk2ZchAAk3
 * This can still be printed on a console, more or less understood by an
 * human and handled with the usual str*() library functions.
 * When you store somewhere the compiled mask you can avoid storing the
 * textform of it since it can be "decompiled" by means of sprintmatch(),
 * but at that time the following things are changed in the mask:
 * - All chars have been forced to lowercase.
 * - The mask is collapsed.
 * The balance point of using compiled masks in terms of CPU is when you expect
 * to use matchexec() instead of match() at least 20 times on the same mask
 * or when you expect to use mmexec() instead of mmatch() 3 times.
 */

/** Compile a mask for faster matching.
 * See also @ref compiledmasks.
 * @param[out] cmask Output buffer for compiled mask.
 * @param[out] minlen Minimum length of matching strings.
 * @param[out] charset Character attributes used in compiled mask.
 * @param[out] mask Input mask.
 * @return Length of compiled mask, not including NUL terminator.
 */
int matchcomp(char *cmask, int *minlen, int *charset, const char *mask)
{
  const char *m = mask;
  char *b = cmask;
  char *fs = 0;
  char *ls = 0;
  char *x1, *x2;
  int l1, l2, lmin, loop, sign;
  int star = 0;
  int cnt = 0;
  char ch;
  int chset = ~0;
  int chset2 = (NTL_LOWER | NTL_UPPER);

  if (m)
    while ((ch = *m++))
      switch (ch)
      {
        case '*':
          star = 1;
          break;
        case '?':
          cnt++;
          *b++ = 'A';
          chset2 &= ~NTL_LOWER;
          break;
        case '\\':
          if ((*m == '?') || (*m == '*'))
            ch = *m++;
        default:
          if (star)
          {
            ls = b;
            fs = fs ? fs : b;
            *b++ = 'Z';
            chset2 &= ~NTL_LOWER;
            star = 0;
          };
          cnt++;
          *b = ToLower(ch);
          chset &= IRCD_CharAttrTab[*b++ - CHAR_MIN];
          chset2 &= ~NTL_UPPER;
      };

  if (charset)
    *charset = (chset | chset2);

  if (star)
  {
    ls = b;
    fs = (fs ? fs : b);
    *b++ = 'Z';
  };

  if (ls)
  {
    for (x1 = ls + 1, x2 = (b - 1); x1 < x2; x1++, x2--)
    {
      ch = *x1;
      *x1 = *x2;
      *x2 = ch;
    };
    l1 = (ls - fs);
    l2 = (b - ls);
    x1 = fs;
    while ((lmin = (l1 < l2) ? l1 : l2))
    {
      x2 = x1 + l1;
      for (loop = 0; loop < lmin; loop++)
      {
        ch = x1[loop];
        x1[loop] = x2[loop];
        x2[loop] = ch;
      };
      x1 += lmin;
      sign = l1 - l2;
      l1 -= (sign < 0) ? 0 : lmin;
      l2 -= (sign > 0) ? 0 : lmin;
    };
  };

  *b = '\0';
  *minlen = cnt;
  return (b - cmask);

}

/** Compare a string to a compiled mask.
 * If \a cmask is not from matchcomp(), or if \a minlen is not the value
 * passed out of matchcomp(), this may core.
 * See also @ref compiledmasks.
 * @param[in] string String to test.
 * @param[in] cmask Compiled mask string.
 * @param[in] minlen Minimum length of strings that match \a cmask.
 * @return Zero if the string matches, non-zero otherwise.
 */
int matchexec(const char *string, const char *cmask, int minlen)
{
  const char *s = string - 1;
  const char *b = cmask - 1;
  int trash;
  const char *bb, *bs;
  char ch;

tryhead:
  while ((ToLower(*++s) == *++b) && *s);
  if (!*s)
    return ((*b != '\0') && ((*b++ != 'Z') || (*b != '\0')));
  if (*b != 'Z')
  {
    if (*b == 'A')
      goto tryhead;
    return 1;
  };

  bs = s;
  while (*++s);

  if ((trash = (s - string - minlen)) < 0)
    return 2;

trytail:
  while ((ToLower(*--s) == *++b) && *b && (ToLower(*--s) == *++b) && *b
      && (ToLower(*--s) == *++b) && *b && (ToLower(*--s) == *++b) && *b);
  if (*b != 'Z')
  {
    if (*b == 'A')
      goto trytail;
    return (*b != '\0');
  };

  s = --bs;
  bb = b;

  while ((ch = *++b))
  {
    while ((ToLower(*++s) != ch))
      if (--trash < 0)
        return 4;
    bs = s;

trychunk:
    while ((ToLower(*++s) == *++b) && *b);
    if (!*b)
      return 0;
    if (*b == 'Z')
    {
      bs = --s;
      bb = b;
      continue;
    };
    if (*b == 'A')
      goto trychunk;

    b = bb;
    s = bs;
    if (--trash < 0)
      return 5;
  };

  return 0;
}

/*
 * matchdecomp()
 * Prints the human readable version of *cmask into *mask, (decompiles
 * cmask).
 * The area pointed by *mask MUST be big enough (the mask might be up to
 * twice the size of its compiled form if it's made all of \? or \*, and
 * this function can NOT work in place since it might inflate the mask)
 * The printed mask is not identical to the one that was compiled to cmask,
 * in fact it is 1) forced to all lowercase, 2) collapsed, both things
 * are supposed to NOT change it's meaning.
 * It returns the number of chars actually written to *mask;
 */

/** Decompile a compiled mask into printable form.
 * See also @ref compiledmasks.
 * @param[out] mask Output mask buffer.
 * @param[in] cmask Compiled mask.
 * @return Number of characters written to \a mask.
 */
int matchdecomp(char *mask, const char *cmask)
{
  char *rtb = mask;
  const char *rcm = cmask;
  const char *begtail, *endtail;

  if (rtb ==0)
    return (-1);

  if (rcm == 0)
    return (-2);

  for (; (*rcm != 'Z'); rcm++, rtb++)
  {
    if ((*rcm == '?') || (*rcm == '*'))
      *rtb++ = '\\';
    if (!((*rtb = ((*rcm == 'A') ? '?' : *rcm))))
      return (rtb - mask);
  };

  begtail = rcm++;
  *rtb++ = '*';

  while (*rcm && (*rcm != 'Z'))
    rcm++;

  endtail = rcm;

  if (*rcm)
  {
    while (*++rcm)
      switch (*rcm)
      {
        case 'A':
          *rtb++ = '?';
          break;
        case 'Z':
          *rtb++ = '*';
          break;
        case '*':
        case '?':
          *rtb++ = '\\';
        default:
          *rtb++ = *rcm;
      };
    *rtb++ = '*';
  };

  for (rcm = endtail; (--rcm) > begtail; *rtb++ = ((*rcm == 'A') ? '?' : *rcm))
    if ((*rcm == '?') || (*rcm == '*'))
      *rtb++ = '\\';

  *rtb = '\0';
  return (rtb - mask);
}

/*
 * mmexec()
 * Checks if a wider compiled mask (wcm/wminlen) completely overrides
 * a more restrict one (rcm/rminlen), basically what mmatch() does for
 * non-compiled masks, returns 0 if the override is true (like mmatch()).
 * "the wider overrides the restrict" means that any string that matches
 * the restrict one _will_ also match the wider one, always. 
 * In this we behave differently from mmatch() because in example we return 
 * true for " a?*cd overrides a*bcd " for which the override happens for how 
 * we literally defined it, here mmatch() would have returned false.
 * The original concepts and the base algorithm are copied from mmatch() 
 * written by Run (Carlo Wood), this function is written by
 * Nemesi (Andrea Cocito)
 */
/** Tests for a superset relationship between compiled masks.  This
 * function does for compiled masks what mmatch() is does for normal
 * masks.
 * See also @ref compiledmasks.
 * @param[in] wcm Compiled mask believed to be wider.
 * @param[in] wminlen Minimum match length for \a wcm.
 * @param[in] rcm Compiled mask believed to be restricted.
 * @param[in] rminlen Minimum match length for \a rcm.
 * @return Zero if \a wcm is a superset of \a rcm, non-zero if not.
 */
int mmexec(const char *wcm, int wminlen, const char *rcm, int rminlen)
{
  const char *w, *r, *br, *bw, *rx, *rz;
  int eat, trash;

  /* First of all rm must have enough non-stars to 'contain' wm */
  if ((trash = rminlen - wminlen) < 0)
    return 1;
  w = wcm;
  r = rcm;
  eat = 0;

  /* Let's start the game, remember that '*' is mapped to 'Z', '?'
     is mapped to 'A' and that head?*??*?chunk*???*tail becomes
     headAAAAZliatAAAZchunk for compiled masks */

  /* Match the head of wm with the head of rm */
  for (; (*r) && (*r != 'Z') && ((*w == *r) || (*w == 'A')); r++, w++);
  if (*r == 'Z')
    while (*w == 'A')           /* Eat extra '?' before '*' in wm if got '*' in rm */
      w++, eat++;
  if (*w != 'Z')                /* head1<any>.. can't match head2<any>.. */
    return ((*w) || (*r)) ? 1 : 0;      /* and head<nul> matches only head<nul> */
  if (!*++w)
    return 0;                   /* headZ<nul> matches head<anything>    */

  /* Does rm have any stars in it ? let's check */
  for (rx = r; *r && (*r != 'Z'); r++);
  if (!*r)
  {
    /* rm has no stars and thus isn't a mask but it's just a flat
       string: special handling occurs here, note that eat must be 0 here */

    /* match the tail */
    if (*w != 'Z')
    {
      for (; r--, (*w) && ((*w == *r) || (*w == 'A')); w++);
      if (*w != 'Z')            /* headZliat1<any> fails on head<any>2tail  */
        return (*w) ? 1 : 0;    /* but headZliat<nul> matches head<any>tail */
    }

    /* match the chunks */
    while (1)
    {                           /* This loop can't break but only return   */

      for (bw = w++; (*w != *rx); rx++) /* Seek the 1st char of the chunk */
        if (--trash < 0)        /* See if we can trash one more char of rm */
          return 1;             /* If not we can only fail of course       */
      for (r = ++rx, w++; (*w) && ((*w == *r) || (*w == 'A')); r++, w++);
      if (!*w)                  /* Did last loop match the rest of chunk ? */
        return 0;               /* ... Yes, end of wm, matched !           */
      if (*w != 'Z')
      {                         /* ... No, hit non-star                    */
        w = bw;                 /* Rollback at beginning of chunk          */
        if (--trash < 0)        /* Trashed the char where this try started */
          return 1;             /* if we can't trash more chars fail       */
      }
      else
      {
        rx = r;                 /* Successfully matched a chunk, move rx   */
      }                 /* and go on with the next one             */
    }
  }

  /* rm has at least one '*' and thus is a 'real' mask */
  rz = r++;                     /* rx = unused of head, rz = beg-tail */

  /* Match the tail of wm (if any) against the tail of rm */
  if (*w != 'Z')
  {
    for (; (*w) && (*r != 'Z') && ((*w == *r) || (*w == 'A')); w++, r++);
    if (*r == 'Z')              /* extra '?' before tail are fluff, just flush 'em */
      while (*w == 'A')
        w++;
    if (*w != 'Z')              /* We aren't matching a chunk, can't rollback      */
      return (*w) ? 1 : 0;
  }

  /* Match the chunks of wm against what remains of the head of rm */
  while (1)
  {
    bw = w;
    for (bw++; (rx < rz) && (*bw != *rx); rx++) /* Seek the first           */
      if (--trash < 0)          /* waste some trash reserve */
        return 1;
    if (!(rx < rz))             /* head finished            */
      break;
    for (bw++, (br = ++rx);
        (br < rz) && (*bw) && ((*bw == *br) || (*bw == 'A')); br++, bw++);
    if (!(br < rz))             /* Note that we didn't use any 'eat' char yet, if  */
      while (*bw == 'A')        /* there were eat-en chars the head would be over  */
        bw++, eat++;            /* Happens only at end of head, and eat is still 0 */
    if (!*bw)
      return 0;
    if (*bw != 'Z')
    {
      eat = 0;
      if (!(br < rz))
      {                         /* If we failed because we got the end of head */
        trash -= (br - rx);     /* it makes no sense to rollback, just trash   */
        if (--trash < 0)        /* all the rest of the head which isn't long   */
          return 1;             /* enough for this chunk and go out of this    */
        break;                  /* loop, then we try with the chunks of rm     */
      };
      if (--trash < 0)
        return 1;
    }
    else
    {
      w = bw;
      rx = br;
    }
  }

  /* Match the unused chunks of wm against the chunks of rm */
  rx = r;
  for (; *r && (*r != 'Z'); r++);
  rz = r;
  if (*r++)
  {
    while (*r)
    {
      bw = w;
      while (eat && *r)         /* the '?' we ate makes us skip as many chars  */
        if (*r++ != 'Z')        /* here, but can't skip stars or trailing zero */
          eat--;
      for (bw++; (*r) && (*bw != *r); r++)
        if ((*r != 'Z') && (--trash < 0))
          return 1;
      if (!*r)
        break;
      for ((br = ++r), bw++;
          (*br) && (*br != 'Z') && ((*bw == *br) || (*bw == 'A')); br++, bw++);
      if (*br == 'Z')
        while (*bw == 'A')
          bw++, eat++;
      if (!*bw)
        return 0;
      if (*bw != 'Z')
      {
        eat = 0;
        if ((!*br) || (*r == 'Z'))
        {                       /* If we hit the end of rm or a star in it */
          trash -= (br - r);    /* makes no sense to rollback within this  */
          if (trash < 0)        /* same chunk of br, skip it all and then  */
            return 1;           /* either rollback or break this loop if   */
          if (!*br)             /* it was the end of rm                    */
            break;
          r = br;
        }
        if (--trash < 0)
          return 1;
      }
      else
      {
        r = br;
        w = bw;
      }
    }
  }

  /* match the remaining chunks of wm against what remains of the tail of rm */
  r = rz - eat - 1;             /* can't have <nul> or 'Z' within the tail, so just move r */
  while (r >= rx)
  {
    bw = w;
    for (bw++; (*bw != *r); r--)
      if (--trash < 0)
        return 1;
    if (!(r >= rx))
      return 1;
    for ((br = --r), bw++;
        (*bw) && (br >= rx) && ((*bw == *br) || (*bw == 'A')); br--, bw++);
    if (!*bw)
      return 0;
    if (!(br >= rx))
      return 1;
    if (*bw != 'Z')
    {
      if (--trash < 0)
        return 1;
    }
    else
    {
      r = br;
      w = bw;
    }
  }
  return 1;                     /* Auch... something left out ? Fail */
}

/** Test whether an address matches the most significant bits of a mask.
 * @param[in] addr Address to test.
 * @param[in] mask Address to test against.
 * @param[in] bits Number of bits to test.
 * @return 0 on mismatch, 1 if bits < 128 and all bits match; -1 if
 * bits == 128 and all bits match.
 */
int ipmask_check(const struct irc_in_addr *addr, const struct irc_in_addr *mask, unsigned char bits)
{
  int k;

  for (k = 0; k < 8; k++) {
    if (bits < 16)
      return !(htons(addr->in6_16[k] ^ mask->in6_16[k]) >> (16-bits));
    if (addr->in6_16[k] != mask->in6_16[k])
      return 0;
    if (!(bits -= 16))
      return 1;
  }
  return -1;
}
