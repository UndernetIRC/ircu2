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
 */
/** @file
 * @brief Implementation of string operations.
 * @version $Id$
 */
#include "config.h"

#include "ircd_string.h"
#include "ircd_defs.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "res.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

/*
 * include the character attribute tables here
 */
#include "chattr.tab.c"

/** Check whether \a str contains wildcard characters.
 * @param[in] str String that might contain wildcards.
 * @return Non-zero if \a str contains naked (non-escaped) wildcards,
 * zero if there are none or if they are all escaped.
 */
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

/** Split a string on certain delimiters.
 * This is a reentrant version of normal strtok().  The first call for
 * a particular input string must use a non-NULL \a str; *save will be
 * initialized based on that.  Later calls must use a NULL \a str;
 * *save will be updated.
 * @param[in,out] save Pointer to a position indicator.
 * @param[in] str Pointer to the input string, or NULL to continue.
 * @param[in] fs String that lists token delimiters.
 * @return Next token in input string, or NULL if no tokens remain.
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

/** Rewrite a comma-delimited list of items to remove duplicates.
 * @param[in,out] buffer Comma-delimited list.
 * @return The input buffer \a buffer.
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

/** Copy one string to another, not to exceed a certain length.
 * @param[in] s1 Output buffer.
 * @param[in] s2 Source buffer.
 * @param[in] n Maximum number of bytes to write, plus one.
 * @return The original input buffer \a s1.
 */
char* ircd_strncpy(char* s1, const char* s2, size_t n)
{
  char* endp = s1 + n;
  char* s = s1;

  assert(0 != s1);
  assert(0 != s2);

  while (s < endp && (*s++ = *s2++))
    ;
  if (s == endp)
    *s = '\0';
  return s1;
}


#ifndef FORCEINLINE
NTL_HDR_strChattr { NTL_SRC_strChattr }
NTL_HDR_strCasediff { NTL_SRC_strCasediff }
#endif /* !FORCEINLINE */

/*
 * Other functions visible externally
 */

/** Case insensitive string comparison.
 * @param[in] a First string to compare.
 * @param[in] b Second string to compare.
 * @return Less than, equal to, or greater than zero if \a a is lexicographically less than, equal to, or greater than \a b.
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
  return (ToLower(*ra) - ToLower(*rb));
}

/** Case insensitive comparison of the starts of two strings.
 * @param[in] a First string to compare.
 * @param[in] b Second string to compare.
 * @param[in] n Maximum number of characters to compare.
 * @return Less than, equal to, or greater than zero if \a a is
 * lexicographically less than, equal to, or greater than \a b.
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
  return (ToLower(*ra) - ToLower(*rb));
}

/** Fill a vector of distinct names from a delimited input list.
 * Empty tokens (when \a token occurs at the start or end of \a list,
 * or when \a token occurs adjacent to itself) are ignored.  When
 * \a size tokens have been written to \a vector, the rest of the
 * string is ignored.
 * Unlike token_vector(), if a token repeats an earlier token, it is
 * skipped.
 * @param[in,out] names Input buffer.
 * @param[in] token Delimiter used to split \a list.
 * @param[out] vector Output vector.
 * @param[in] size Maximum number of elements to put in \a vector.
 * @return Number of elements written to \a vector.
 */
int unique_name_vector(char* names, char token, char** vector, int size)
{
  int   i;
  int   count = 0;
  char* start = names;
  char* end;

  assert(0 != names);
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

/** Fill a vector of tokens from a delimited input list.
 * Empty tokens (when \a token occurs at the start or end of \a list,
 * or when \a token occurs adjacent to itself) are ignored.  When
 * \a size tokens have been written to \a vector, the rest of the
 * string is ignored.
 * @param[in,out] names Input buffer.
 * @param[in] token Delimiter used to split \a list.
 * @param[out] vector Output vector.
 * @param[in] size Maximum number of elements to put in \a vector.
 * @return Number of elements written to \a vector.
 */
int token_vector(char* names, char token, char** vector, int size)
{
  int   count = 0;
  char* start = names;
  char* end;

  assert(0 != names);
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

/** Copy all or part of the hostname in a string to another string.
 * If \a userhost contains an '\@', the remaining portion is used;
 * otherwise, the whole \a userhost is used.
 * @param[out] buf Output buffer.
 * @param[in] userhost user\@hostname or hostname string.
 * @param[in] len Maximum number of bytes to write to \a host.
 * @return The output buffer \a buf.
 */
char* host_from_uh(char* buf, const char* userhost, size_t len)
{
  const char* s;

  assert(0 != buf);
  assert(0 != userhost);

  if ((s = strchr(userhost, '@')))
    ++s;
  else
    s = userhost;
  ircd_strncpy(buf, s, len);
  buf[len] = '\0';
  return buf;
}

/*
 * this new faster inet_ntoa was ripped from:
 * From: Thomas Helvey <tomh@inxpress.net>
 */
/** Array of text strings for dotted quads. */
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

/** Convert an IP address to printable ASCII form.
 * This is generally deprecated in favor of ircd_ntoa_r().
 * @param[in] in Address to convert.
 * @return Pointer to a static buffer containing the readable form.
 */
const char* ircd_ntoa(const struct irc_in_addr* in)
{
  static char buf[SOCKIPLEN];
  return ircd_ntoa_r(buf, in);
}

/** Convert an IP address to printable ASCII form.
 * @param[out] buf Output buffer to write to.
 * @param[in] in Address to format.
 * @return Pointer to the output buffer \a buf.
 */
const char* ircd_ntoa_r(char* buf, const struct irc_in_addr* in)
{
    assert(buf != NULL);
    assert(in != NULL);

    if (irc_in_addr_is_ipv4(in)) {
      unsigned int pos, len;
      unsigned char *pch;

      pch = (unsigned char*)&in->in6_16[6];
      len = strlen(IpQuadTab[*pch]);
      memcpy(buf, IpQuadTab[*pch++], len);
      pos = len;
      buf[pos++] = '.';
      len = strlen(IpQuadTab[*pch]);
      memcpy(buf+pos, IpQuadTab[*pch++], len);
      pos += len;
      buf[pos++] = '.';
      len = strlen(IpQuadTab[*pch]);
      memcpy(buf+pos, IpQuadTab[*pch++], len);
      pos += len;
      buf[pos++] = '.';
      len = strlen(IpQuadTab[*pch]);
      memcpy(buf+pos, IpQuadTab[*pch++], len);
      buf[pos + len] = '\0';
      return buf;
    } else {
      static const char hexdigits[] = "0123456789abcdef";
      unsigned int pos, part, max_start, max_zeros, curr_zeros, ii;

      /* Find longest run of zeros. */
      for (max_start = ii = 1, max_zeros = curr_zeros = 0; ii < 8; ++ii) {
        if (!in->in6_16[ii])
          curr_zeros++;
        else if (curr_zeros > max_zeros) {
          max_start = ii - curr_zeros;
          max_zeros = curr_zeros;
          curr_zeros = 0;
        }
      }
      if (curr_zeros > max_zeros) {
        max_start = ii - curr_zeros;
        max_zeros = curr_zeros;
      }

      /* Print out address. */
/** Append \a CH to the output buffer. */
#define APPEND(CH) do { buf[pos++] = (CH); } while (0)
      for (pos = ii = 0; (ii < 8); ++ii) {
        if ((max_zeros > 0) && (ii == max_start)) {
          APPEND(':');
          ii += max_zeros - 1;
          continue;
        }
        part = ntohs(in->in6_16[ii]);
        if (part >= 0x1000)
          APPEND(hexdigits[part >> 12]);
        if (part >= 0x100)
          APPEND(hexdigits[(part >> 8) & 15]);
        if (part >= 0x10)
          APPEND(hexdigits[(part >> 4) & 15]);
        APPEND(hexdigits[part & 15]);
        if (ii < 7)
          APPEND(':');
      }
#undef APPEND

      /* Nul terminate and return number of characters used. */
      buf[pos++] = '\0';
      return buf;
    }
}

/** Attempt to parse an IPv4 address into a network-endian form.
 * @param[in] input Input string.
 * @param[out] output Network-endian representation of the address.
 * @param[out] pbits Number of bits found in pbits.
 * @return Number of characters used from \a input, or 0 if the parse failed.
 */
static unsigned int
ircd_aton_ip4(const char *input, unsigned int *output, unsigned char *pbits)
{
  unsigned int dots = 0, pos = 0, part = 0, ip = 0, bits;

  /* Intentionally no support for bizarre IPv4 formats (plain
   * integers, octal or hex components) -- only vanilla dotted
   * decimal quads.
   */
  if (input[0] == '.')
    return 0;
  bits = 32;
  while (1) switch (input[pos]) {
  case '\0':
    if (dots < 3)
      return 0;
  out:
    ip |= part << (24 - 8 * dots);
    *output = htonl(ip);
    if (pbits)
      *pbits = bits;
    return pos;
  case '.':
    if (++dots > 3)
      return 0;
    if (input[++pos] == '.')
      return 0;
    ip |= part << (32 - 8 * dots);
    part = 0;
    if (input[pos] == '*') {
      while (input[++pos] == '*' || input[pos] == '.') ;
      if (input[pos] != '\0')
        return 0;
      if (pbits)
        *pbits = dots * 8;
      *output = htonl(ip);
      return pos;
    }
    break;
  case '/':
    if (!pbits || !IsDigit(input[pos + 1]))
      return 0;
    for (bits = 0; IsDigit(input[++pos]); )
      bits = bits * 10 + input[pos] - '0';
    if (bits > 32)
      return 0;
    goto out;
  case '0': case '1': case '2': case '3': case '4':
  case '5': case '6': case '7': case '8': case '9':
    part = part * 10 + input[pos++] - '0';
    if (part > 255)
      return 0;
    break;
  default:
    return 0;
  }
}

/** Parse a numeric IPv4 or IPv6 address into an irc_in_addr.
 * @param[in] input Input buffer.
 * @param[out] ip Receives parsed IP address.
 * @param[out] pbits If non-NULL, receives number of bits specified in address mask.
 * @return Number of characters used from \a input, or 0 if the
 * address was unparseable or malformed.
 */
int
ipmask_parse(const char *input, struct irc_in_addr *ip, unsigned char *pbits)
{
  char *colon;
  char *dot;

  assert(ip);
  assert(input);
  memset(ip, 0, sizeof(*ip));
  colon = strchr(input, ':');
  dot = strchr(input, '.');

  if (colon && (!dot || (dot > colon))) {
    unsigned int part = 0, pos = 0, ii = 0, colon = 8;
    const char *part_start = NULL;

    /* Parse IPv6, possibly like ::127.0.0.1.
     * This is pretty straightforward; the only trick is borrowed
     * from Paul Vixie (BIND): when it sees a "::" continue as if
     * it were a single ":", but note where it happened, and fill
     * with zeros afterward.
     */
    if (input[pos] == ':') {
      if ((input[pos+1] != ':') || (input[pos+2] == ':'))
        return 0;
      colon = 0;
      pos += 2;
      part_start = input + pos;
    }
    while (ii < 8) switch (input[pos]) {
      unsigned char chval;
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      chval = input[pos] - '0';
    use_chval:
      part = (part << 4) | chval;
      if (part > 0xffff)
        return 0;
      pos++;
      break;
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
      chval = input[pos] - 'A' + 10;
      goto use_chval;
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
      chval = input[pos] - 'a' + 10;
      goto use_chval;
    case ':':
      part_start = input + ++pos;
      if (input[pos] == '.')
        return 0;
      ip->in6_16[ii++] = htons(part);
      part = 0;
      if (input[pos] == ':') {
        if (colon < 8)
          return 0;
        if (ii == 8)
            return 0;
        colon = ii;
        pos++;
      }
      break;
    case '.': {
      uint32_t ip4;
      unsigned int len;
      len = ircd_aton_ip4(part_start, &ip4, pbits);
      if (!len || (ii > 6))
        return 0;
      ip->in6_16[ii++] = htons(ntohl(ip4) >> 16);
      ip->in6_16[ii++] = htons(ntohl(ip4) & 65535);
      if (pbits)
        *pbits += 96;
      pos = part_start + len - input;
      goto finish;
    }
    case '/':
      if (!pbits || !IsDigit(input[pos + 1]))
        return 0;
      ip->in6_16[ii++] = htons(part);
      for (part = 0; IsDigit(input[++pos]); )
        part = part * 10 + input[pos] - '0';
      if (part > 128)
        return 0;
      *pbits = part;
      goto finish;
    case '*':
      while (input[++pos] == '*' || input[pos] == ':') ;
      if (input[pos] != '\0' || colon < 8)
        return 0;
      if (part && ii < 8)
          ip->in6_16[ii++] = htons(part);
      if (pbits)
        *pbits = ii * 16;
      return pos;
    case '\0':
      ip->in6_16[ii++] = htons(part);
      if (colon == 8 && ii < 8)
        return 0;
      if (pbits)
        *pbits = 128;
      goto finish;
    default:
      return 0;
    }
    if (input[pos] != '\0')
      return 0;
  finish:
    if (colon < 8) {
      unsigned int jj;
      /* Shift stuff after "::" up and fill middle with zeros. */
      for (jj = 0; jj < ii - colon; jj++)
        ip->in6_16[7 - jj] = ip->in6_16[ii - jj - 1];
      for (jj = 0; jj < 8 - ii; jj++)
        ip->in6_16[colon + jj] = 0;
    }
    return pos;
  } else if (dot || strchr(input, '/')) {
    unsigned int addr;
    int len = ircd_aton_ip4(input, &addr, pbits);
    if (len) {
      ip->in6_16[5] = htons(65535);
      ip->in6_16[6] = htons(ntohl(addr) >> 16);
      ip->in6_16[7] = htons(ntohl(addr) & 65535);
      if (pbits)
        *pbits += 96;
    }
    return len;
  } else if (input[0] == '*') {
    unsigned int pos = 0;
    while (input[++pos] == '*') ;
    if (input[pos] != '\0')
      return 0;
    if (pbits)
      *pbits = 0;
    return pos;
  } else return 0; /* parse failed */
}
