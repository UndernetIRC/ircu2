/*
 * IRC - Internet Relay Chat, ircd/ircd_string.c
 * Copyright (C) 1999 Thomas Helvey
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
 *
 * $Id$
 */
#include "config.h"

#include "ircd_string.h"
#include "ircd_defs.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include <assert.h>
#include <string.h>
#include <regex.h>
/*
 * include the character attribute tables here
 */
#include "chattr.tab.c"


/*
 * Disallow a hostname label to contain anything but a [-a-zA-Z0-9].
 * It may not start or end on a '.'.
 * A label may not end on a '-', the maximum length of a label is
 * 63 characters.
 * On top of that (which seems to be the RFC) we demand that the
 * top domain does not contain any digits.
 */
static const char* hostExpr = "^([-0-9A-Za-z]*[0-9A-Za-z]\\.)+[A-Za-z]+$";
static regex_t hostRegex;

static const char* addrExpr =
    "^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){1,3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$";
static regex_t addrRegex;

int init_string(void)
{
  /*
   * initialize matching expressions
   * XXX - expressions MUST be correct, don't change expressions
   * without testing them. Might be a good idea to exit if these fail,
   * important code depends on them.
   * TODO: use regerror for an error message
   */
  if (regcomp(&hostRegex, hostExpr, REG_EXTENDED | REG_NOSUB))
    return 0;

  if (regcomp(&addrRegex, addrExpr, REG_EXTENDED | REG_NOSUB))
    return 0;
  return 1;
}

int string_is_hostname(const char* str)
{
  assert(0 != str);
  return (strlen(str) <= HOSTLEN && 0 == regexec(&hostRegex, str, 0, 0, 0));
}

int string_is_address(const char* str)
{
  assert(0 != str);
  return (0 == regexec(&addrRegex, str, 0, 0, 0));
}

int string_has_wildcards(const char* str)
{
  assert(0 != str);
  for ( ; *str; ++str) {
    if ('\\' == *str) {
      if ('\0' == *++str)
        break;
    }
    else if ('*' == *str || '?' == *str)
      return 1;
  }
  return 0;
}

/*
 * strtoken.c
 *
 * Walk through a string of tokens, using a set of separators.
 * -argv 9/90
 */
char* ircd_strtok(char **save, char *str, char *fs)
{
  char *pos = *save;            /* keep last position across calls */
  char *tmp;

  if (str)
    pos = str;                  /* new string scan */

  while (pos && *pos && strchr(fs, *pos) != NULL)
    pos++;                      /* skip leading separators */

  if (!pos || !*pos)
    return (pos = *save = NULL);        /* string contains only sep's */

  tmp = pos;                    /* now, keep position of the token */

  while (*pos && strchr(fs, *pos) == NULL)
    pos++;                      /* skip content of the token */

  if (*pos)
    *pos++ = '\0';              /* remove first sep after the token */
  else
    pos = NULL;                 /* end of string */

  *save = pos;
  return (tmp);
}

/*
 * canonize
 *
 * reduce a string of duplicate list entries to contain only the unique
 * items.  Unavoidably O(n^2).
 */
char* canonize(char* buffer)
{
  static char cbuf[BUFSIZE];
  char*       s;
  char*       t;
  char*       cp = cbuf;
  int         l = 0;
  char*       p = NULL;
  char*       p2;

  *cp = '\0';

  for (s = ircd_strtok(&p, buffer, ","); s; s = ircd_strtok(&p, NULL, ","))
  {
    if (l)
    {
      p2 = NULL;
      for (t = ircd_strtok(&p2, cbuf, ","); t; t = ircd_strtok(&p2, NULL, ","))
        if (0 == ircd_strcmp(s, t))
          break;
        else if (p2)
          p2[-1] = ',';
    }
    else
      t = NULL;
    if (!t)
    {
      if (l)
        *(cp - 1) = ',';
      else
        l = 1;
      strcpy(cp, s);
      if (p)
        cp += (p - s);
    }
    else if (p2)
      p2[-1] = ',';
  }
  return cbuf;
}

/*
 * ircd_strncpy - optimized strncpy
 * This may not look like it would be the fastest possible way to do it,
 * but it generally outperforms everything else on many platforms,
 * including asm library versions and memcpy, if compiled with the
 * optimizer on. (-O2 for gcc) --Bleep
 */
char* ircd_strncpy(char* s1, const char* s2, size_t n)
{
  char* endp = s1 + n;
  char* s = s1;

  assert(0 != s1);
  assert(0 != s2);

  while (s < endp && (*s++ = *s2++))
    ;
  return s1;
}


#ifndef FORCEINLINE
NTL_HDR_strChattr { NTL_SRC_strChattr }
NTL_HDR_strCasediff { NTL_SRC_strCasediff }
#endif /* !FORCEINLINE */

/*
 * Other functions visible externally
 */

int strnChattr(const char *s, size_t n)
{
  const char *rs = s;
  unsigned int x = ~0;
  int r = n;
  while (*rs && r--)
    x &= IRCD_CharAttrTab[*rs++ - CHAR_MIN];
  return x;
}

/*
 * ircd_strcmp - case insensitive comparison of 2 strings
 * NOTE: see ircd_chattr.h for notes on case mapping.
 */
int ircd_strcmp(const char *a, const char *b)
{
  const char* ra = a;
  const char* rb = b;
  while (ToLower(*ra) == ToLower(*rb)) {
    if (!*ra++)
      return 0;
    else
      ++rb;
  }
  return (*ra - *rb);
}

/*
 * ircd_strncmp - counted case insensitive comparison of 2 strings
 * NOTE: see ircd_chattr.h for notes on case mapping.
 */
int ircd_strncmp(const char *a, const char *b, size_t n)
{
  const char* ra = a;
  const char* rb = b;
  int left = n;
  if (!left--)
    return 0;
  while (ToLower(*ra) == ToLower(*rb)) {
    if (!*ra++ || !left--)
      return 0;
    else
      ++rb;
  }
  return (*ra - *rb);
}

/*
 * unique_name_vector - create a unique vector of names from
 * a token separated list
 * list   - [in]  a token delimited null terminated character array
 * token  - [in]  the token to replace 
 * vector - [out] vector of strings to be returned
 * size   - [in]  maximum number of elements to place in vector
 * Returns count of elements placed into the vector, if the list
 * is an empty string { '\0' } 0 is returned.
 * list, and vector must be non-null and size must be > 0 
 * Empty strings <token><token> are not placed in the vector or counted.
 * This function ignores all subsequent tokens when count == size
 *
 * NOTE: this function destroys it's input, do not use list after it
 * is passed to this function
 */
int unique_name_vector(char* list, char token, char** vector, int size)
{
  int   i;
  int   count = 0;
  char* start = list;
  char* end;

  assert(0 != list);
  assert(0 != vector);
  assert(0 < size);
 
  /*
   * ignore spurious tokens
   */
  while (token == *start)
    ++start;

  for (end = strchr(start, token); end; end = strchr(start, token)) {
    *end++ = '\0';
    /*
     * ignore spurious tokens
     */
    while (token == *end)
      ++end;
    for (i = 0; i < count; ++i) {
      if (0 == ircd_strcmp(vector[i], start))
        break;
    }
    if (i == count) {
      vector[count++] = start;
      if (count == size)
        return count;
    }
    start = end;
  }
  if (*start) {
    for (i = 0; i < count; ++i)
      if (0 == ircd_strcmp(vector[i], start))
        return count;
    vector[count++] = start;
  }
  return count;
}

/*
 * token_vector - create a vector of tokens from
 * a token separated list
 * list   - [in]  a token delimited null terminated character array
 * token  - [in]  the token to replace 
 * vector - [out] vector of strings to be returned
 * size   - [in]  maximum number of elements to place in vector
 * returns count of elements placed into the vector, if the list
 * is an empty string { '\0' } 0 is returned.
 * list, and vector must be non-null and size must be > 1 
 * Empty tokens are counted and placed in the list
 *
 * NOTE: this function destroys it's input, do not use list after it
 * is passed to this function
 */
int token_vector(char* list, char token, char** vector, int size)
{
  int   count = 0;
  char* start = list;
  char* end;

  assert(0 != list);
  assert(0 != vector);
  assert(1 < size);
 
  vector[count++] = start;
  for (end = strchr(start, token); end; end = strchr(start, token)) {
    *end++ = '\0';
    start = end;
    if (*start) {
      vector[count++] = start;
      if (count < size)
        continue;
    }
    break;
  }
  return count;
} 

/*
 * host_from_uh - get the host.domain part of a user@host.domain string
 * ripped from get_sockhost
 */
char* host_from_uh(char* host, const char* userhost, size_t n)
{
  const char* s;

  assert(0 != host);
  assert(0 != userhost);

  if ((s = strchr(userhost, '@')))
    ++s;
  else
    s = userhost;
  ircd_strncpy(host, s, n);
  host[n] = '\0';
  return host;
}

/* 
 * this new faster inet_ntoa was ripped from:
 * From: Thomas Helvey <tomh@inxpress.net>
 */
static const char* IpQuadTab[] =
{
    "0",   "1",   "2",   "3",   "4",   "5",   "6",   "7",   "8",   "9",
   "10",  "11",  "12",  "13",  "14",  "15",  "16",  "17",  "18",  "19",
   "20",  "21",  "22",  "23",  "24",  "25",  "26",  "27",  "28",  "29",
   "30",  "31",  "32",  "33",  "34",  "35",  "36",  "37",  "38",  "39",
   "40",  "41",  "42",  "43",  "44",  "45",  "46",  "47",  "48",  "49",
   "50",  "51",  "52",  "53",  "54",  "55",  "56",  "57",  "58",  "59",
   "60",  "61",  "62",  "63",  "64",  "65",  "66",  "67",  "68",  "69",
   "70",  "71",  "72",  "73",  "74",  "75",  "76",  "77",  "78",  "79",
   "80",  "81",  "82",  "83",  "84",  "85",  "86",  "87",  "88",  "89",
   "90",  "91",  "92",  "93",  "94",  "95",  "96",  "97",  "98",  "99",
  "100", "101", "102", "103", "104", "105", "106", "107", "108", "109",
  "110", "111", "112", "113", "114", "115", "116", "117", "118", "119",
  "120", "121", "122", "123", "124", "125", "126", "127", "128", "129",
  "130", "131", "132", "133", "134", "135", "136", "137", "138", "139",
  "140", "141", "142", "143", "144", "145", "146", "147", "148", "149",
  "150", "151", "152", "153", "154", "155", "156", "157", "158", "159",
  "160", "161", "162", "163", "164", "165", "166", "167", "168", "169",
  "170", "171", "172", "173", "174", "175", "176", "177", "178", "179",
  "180", "181", "182", "183", "184", "185", "186", "187", "188", "189",
  "190", "191", "192", "193", "194", "195", "196", "197", "198", "199",
  "200", "201", "202", "203", "204", "205", "206", "207", "208", "209",
  "210", "211", "212", "213", "214", "215", "216", "217", "218", "219",
  "220", "221", "222", "223", "224", "225", "226", "227", "228", "229",
  "230", "231", "232", "233", "234", "235", "236", "237", "238", "239",
  "240", "241", "242", "243", "244", "245", "246", "247", "248", "249",
  "250", "251", "252", "253", "254", "255"
};

/*
 * ircd_ntoa - rewrote and renamed yet again :) --Bleep
 * inetntoa - in_addr to string
 *      changed name to remove collision possibility and
 *      so behaviour is guaranteed to take a pointer arg.
 *      -avalon 23/11/92
 *  inet_ntoa --  returned the dotted notation of a given
 *      internet number
 *      argv 11/90).
 *  inet_ntoa --  its broken on some Ultrix/Dynix too. -avalon
 */
const char* ircd_ntoa(const char* in)
{
  static char buf[20];
  return ircd_ntoa_r(buf, in);
}

/*
 * reentrant version of above
 */
const char* ircd_ntoa_r(char* buf, const char* in)
{
  char*                p = buf;
  const unsigned char* a = (const unsigned char*)in;
  const char*          n;

  assert(0 != buf);
  assert(0 != in);

  n = IpQuadTab[*a++];
  while ((*p = *n++))
    ++p;
  *p++ = '.';
  n = IpQuadTab[*a++];
  while ((*p = *n++))
    ++p;
  *p++ = '.';
  n = IpQuadTab[*a++];
  while ((*p = *n++))
    ++p;
  *p++ = '.';
  n = IpQuadTab[*a];
  while ((*p = *n++))
    ++p;
  return buf;
}


