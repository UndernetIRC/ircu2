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
 * CODERS WARNING: DO _NOT_ EDIT THE TABLES IN THIS FILE
 * Instead:
 * a) Edit the table generator below, specifically the makeTables() function
 * b) Recreate the common.c tables with 'make ctables'.
 */


/*=============================================================================
 * Actual source of the library stuff, not generated when making the tables
 */

#ifndef MAKETABLES

/*=============================================================================
 * Headers needed in this source file
 */

#include "common.h"

/*=============================================================================
 * Functions eventually inlined or visible externally
 */

#ifndef FORCEINLINE
/* *INDENT-OFF* */
NTL_HDR_strChattr { NTL_SRC_strChattr }
NTL_HDR_strCasediff { NTL_SRC_strCasediff }
/* *INDENT-ON* */
#endif /* !FORCEINLINE */

/*=============================================================================
 * Other functions visible externally
 */

int strnChattr(const char *s, const size_t n)
{
  register const char *rs = s;
  register int x = ~0;
  register int r = n;
  while (*rs && r--)
    x &= NTL_char_attrib[*rs++ - CHAR_MIN];
  return x;
}

int strCasecmp(const char *a, const char *b)
{
  register const char *ra = a;
  register const char *rb = b;
  while (toLower(*ra) == toLower(*rb))
    if (!*ra++)
      return 0;
    else
      rb++;
  return (*ra - *rb);
}

int strnCasecmp(const char *a, const char *b, const size_t n)
{
  register const char *ra = a;
  register const char *rb = b;
  register int left = n;
  if (!left--)
    return 0;
  while (toLower(*ra) == toLower(*rb))
    if ((!(*(ra++))) || (!(left--)))
      return 0;
    else
      rb++;
  return (*ra - *rb);
}

/*=============================================================================
 * Automatically generated tables, don't touch these by hand !
 */

/* *INDENT-OFF* */
/*
 * DO not touch anything below this line !
 * NTL_TOK_START
 */
const char NTL_tolower_tab[] = {
#if (CHAR_MIN<0)
/* x80-x87 */ '\x80', '\x81', '\x82', '\x83', '\x84', '\x85', '\x86', '\x87',
/* x88-x8f */ '\x88', '\x89', '\x8a', '\x8b', '\x8c', '\x8d', '\x8e', '\x8f',
/* x90-x97 */ '\x90', '\x91', '\x92', '\x93', '\x94', '\x95', '\x96', '\x97',
/* x98-x9f */ '\x98', '\x99', '\x9a', '\x9b', '\x9c', '\x9d', '\x9e', '\x9f',
/* xa0-xa7 */ '\xa0', '\xa1', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6', '\xa7',
/* xa8-xaf */ '\xa8', '\xa9', '\xaa', '\xab', '\xac', '\xad', '\xae', '\xaf',
/* xb0-xb7 */ '\xb0', '\xb1', '\xb2', '\xb3', '\xb4', '\xb5', '\xb6', '\xb7',
/* xb8-xbf */ '\xb8', '\xb9', '\xba', '\xbb', '\xbc', '\xbd', '\xbe', '\xbf',
/* xc0-xc7 */ '\xe0', '\xe1', '\xe2', '\xe3', '\xe4', '\xe5', '\xe6', '\xe7',
/* xc8-xcf */ '\xe8', '\xe9', '\xea', '\xeb', '\xec', '\xed', '\xee', '\xef',
/* xd0-xd7 */ '\xd0', '\xf1', '\xf2', '\xf3', '\xf4', '\xf5', '\xf6', '\xd7',
/* xd8-xdf */ '\xf8', '\xf9', '\xfa', '\xfb', '\xfc', '\xfd', '\xfe', '\xdf',
/* xe0-xe7 */ '\xe0', '\xe1', '\xe2', '\xe3', '\xe4', '\xe5', '\xe6', '\xe7',
/* xe8-xef */ '\xe8', '\xe9', '\xea', '\xeb', '\xec', '\xed', '\xee', '\xef',
/* xf0-xf7 */ '\xf0', '\xf1', '\xf2', '\xf3', '\xf4', '\xf5', '\xf6', '\xf7',
/* xf8-xff */ '\xf8', '\xf9', '\xfa', '\xfb', '\xfc', '\xfd', '\xfe', '\xff'
                ,
#endif /* (CHAR_MIN<0) */
/* x00-x07 */ '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
/* x08-x0f */ '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f',
/* x10-x17 */ '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17',
/* x18-x1f */ '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f',
/* ' '-x27 */    ' ',    '!',    '"',    '#',    '$',    '%',    '&', '\x27',
/* '('-'/' */    '(',    ')',    '*',    '+',    ',',    '-',    '.',    '/',
/* '0'-'7' */    '0',    '1',    '2',    '3',    '4',    '5',    '6',    '7',
/* '8'-'?' */    '8',    '9',    ':',    ';',    '<',    '=',    '>',    '?',
/* '@'-'G' */    '@',    'a',    'b',    'c',    'd',    'e',    'f',    'g',
/* 'H'-'O' */    'h',    'i',    'j',    'k',    'l',    'm',    'n',    'o',
/* 'P'-'W' */    'p',    'q',    'r',    's',    't',    'u',    'v',    'w',
/* 'X'-'_' */    'x',    'y',    'z',    '{',    '|',    '}',    '~',    '_',
/* '`'-'g' */    '`',    'a',    'b',    'c',    'd',    'e',    'f',    'g',
/* 'h'-'o' */    'h',    'i',    'j',    'k',    'l',    'm',    'n',    'o',
/* 'p'-'w' */    'p',    'q',    'r',    's',    't',    'u',    'v',    'w',
/* 'x'-x7f */    'x',    'y',    'z',    '{',    '|',    '}',    '~', '\x7f'
#if (!(CHAR_MIN<0))
                ,
/* x80-x87 */ '\x80', '\x81', '\x82', '\x83', '\x84', '\x85', '\x86', '\x87',
/* x88-x8f */ '\x88', '\x89', '\x8a', '\x8b', '\x8c', '\x8d', '\x8e', '\x8f',
/* x90-x97 */ '\x90', '\x91', '\x92', '\x93', '\x94', '\x95', '\x96', '\x97',
/* x98-x9f */ '\x98', '\x99', '\x9a', '\x9b', '\x9c', '\x9d', '\x9e', '\x9f',
/* xa0-xa7 */ '\xa0', '\xa1', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6', '\xa7',
/* xa8-xaf */ '\xa8', '\xa9', '\xaa', '\xab', '\xac', '\xad', '\xae', '\xaf',
/* xb0-xb7 */ '\xb0', '\xb1', '\xb2', '\xb3', '\xb4', '\xb5', '\xb6', '\xb7',
/* xb8-xbf */ '\xb8', '\xb9', '\xba', '\xbb', '\xbc', '\xbd', '\xbe', '\xbf',
/* xc0-xc7 */ '\xe0', '\xe1', '\xe2', '\xe3', '\xe4', '\xe5', '\xe6', '\xe7',
/* xc8-xcf */ '\xe8', '\xe9', '\xea', '\xeb', '\xec', '\xed', '\xee', '\xef',
/* xd0-xd7 */ '\xd0', '\xf1', '\xf2', '\xf3', '\xf4', '\xf5', '\xf6', '\xd7',
/* xd8-xdf */ '\xf8', '\xf9', '\xfa', '\xfb', '\xfc', '\xfd', '\xfe', '\xdf',
/* xe0-xe7 */ '\xe0', '\xe1', '\xe2', '\xe3', '\xe4', '\xe5', '\xe6', '\xe7',
/* xe8-xef */ '\xe8', '\xe9', '\xea', '\xeb', '\xec', '\xed', '\xee', '\xef',
/* xf0-xf7 */ '\xf0', '\xf1', '\xf2', '\xf3', '\xf4', '\xf5', '\xf6', '\xf7',
/* xf8-xff */ '\xf8', '\xf9', '\xfa', '\xfb', '\xfc', '\xfd', '\xfe', '\xff'
#endif /* (!(CHAR_MIN<0)) */
  };

const char NTL_toupper_tab[] = {
#if (CHAR_MIN<0)
/* x80-x87 */ '\x80', '\x81', '\x82', '\x83', '\x84', '\x85', '\x86', '\x87',
/* x88-x8f */ '\x88', '\x89', '\x8a', '\x8b', '\x8c', '\x8d', '\x8e', '\x8f',
/* x90-x97 */ '\x90', '\x91', '\x92', '\x93', '\x94', '\x95', '\x96', '\x97',
/* x98-x9f */ '\x98', '\x99', '\x9a', '\x9b', '\x9c', '\x9d', '\x9e', '\x9f',
/* xa0-xa7 */ '\xa0', '\xa1', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6', '\xa7',
/* xa8-xaf */ '\xa8', '\xa9', '\xaa', '\xab', '\xac', '\xad', '\xae', '\xaf',
/* xb0-xb7 */ '\xb0', '\xb1', '\xb2', '\xb3', '\xb4', '\xb5', '\xb6', '\xb7',
/* xb8-xbf */ '\xb8', '\xb9', '\xba', '\xbb', '\xbc', '\xbd', '\xbe', '\xbf',
/* xc0-xc7 */ '\xc0', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6', '\xc7',
/* xc8-xcf */ '\xc8', '\xc9', '\xca', '\xcb', '\xcc', '\xcd', '\xce', '\xcf',
/* xd0-xd7 */ '\xd0', '\xd1', '\xd2', '\xd3', '\xd4', '\xd5', '\xd6', '\xd7',
/* xd8-xdf */ '\xd8', '\xd9', '\xda', '\xdb', '\xdc', '\xdd', '\xde', '\xdf',
/* xe0-xe7 */ '\xc0', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6', '\xc7',
/* xe8-xef */ '\xc8', '\xc9', '\xca', '\xcb', '\xcc', '\xcd', '\xce', '\xcf',
/* xf0-xf7 */ '\xf0', '\xd1', '\xd2', '\xd3', '\xd4', '\xd5', '\xd6', '\xf7',
/* xf8-xff */ '\xd8', '\xd9', '\xda', '\xdb', '\xdc', '\xdd', '\xde', '\xff'
                ,
#endif /* (CHAR_MIN<0) */
/* x00-x07 */ '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
/* x08-x0f */ '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f',
/* x10-x17 */ '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17',
/* x18-x1f */ '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f',
/* ' '-x27 */    ' ',    '!',    '"',    '#',    '$',    '%',    '&', '\x27',
/* '('-'/' */    '(',    ')',    '*',    '+',    ',',    '-',    '.',    '/',
/* '0'-'7' */    '0',    '1',    '2',    '3',    '4',    '5',    '6',    '7',
/* '8'-'?' */    '8',    '9',    ':',    ';',    '<',    '=',    '>',    '?',
/* '@'-'G' */    '@',    'A',    'B',    'C',    'D',    'E',    'F',    'G',
/* 'H'-'O' */    'H',    'I',    'J',    'K',    'L',    'M',    'N',    'O',
/* 'P'-'W' */    'P',    'Q',    'R',    'S',    'T',    'U',    'V',    'W',
/* 'X'-'_' */    'X',    'Y',    'Z',    '[', '\x5c',    ']',    '^',    '_',
/* '`'-'g' */    '`',    'A',    'B',    'C',    'D',    'E',    'F',    'G',
/* 'h'-'o' */    'H',    'I',    'J',    'K',    'L',    'M',    'N',    'O',
/* 'p'-'w' */    'P',    'Q',    'R',    'S',    'T',    'U',    'V',    'W',
/* 'x'-x7f */    'X',    'Y',    'Z',    '[', '\x5c',    ']',    '^', '\x7f'
#if (!(CHAR_MIN<0))
                ,
/* x80-x87 */ '\x80', '\x81', '\x82', '\x83', '\x84', '\x85', '\x86', '\x87',
/* x88-x8f */ '\x88', '\x89', '\x8a', '\x8b', '\x8c', '\x8d', '\x8e', '\x8f',
/* x90-x97 */ '\x90', '\x91', '\x92', '\x93', '\x94', '\x95', '\x96', '\x97',
/* x98-x9f */ '\x98', '\x99', '\x9a', '\x9b', '\x9c', '\x9d', '\x9e', '\x9f',
/* xa0-xa7 */ '\xa0', '\xa1', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6', '\xa7',
/* xa8-xaf */ '\xa8', '\xa9', '\xaa', '\xab', '\xac', '\xad', '\xae', '\xaf',
/* xb0-xb7 */ '\xb0', '\xb1', '\xb2', '\xb3', '\xb4', '\xb5', '\xb6', '\xb7',
/* xb8-xbf */ '\xb8', '\xb9', '\xba', '\xbb', '\xbc', '\xbd', '\xbe', '\xbf',
/* xc0-xc7 */ '\xc0', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6', '\xc7',
/* xc8-xcf */ '\xc8', '\xc9', '\xca', '\xcb', '\xcc', '\xcd', '\xce', '\xcf',
/* xd0-xd7 */ '\xd0', '\xd1', '\xd2', '\xd3', '\xd4', '\xd5', '\xd6', '\xd7',
/* xd8-xdf */ '\xd8', '\xd9', '\xda', '\xdb', '\xdc', '\xdd', '\xde', '\xdf',
/* xe0-xe7 */ '\xc0', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6', '\xc7',
/* xe8-xef */ '\xc8', '\xc9', '\xca', '\xcb', '\xcc', '\xcd', '\xce', '\xcf',
/* xf0-xf7 */ '\xf0', '\xd1', '\xd2', '\xd3', '\xd4', '\xd5', '\xd6', '\xf7',
/* xf8-xff */ '\xd8', '\xd9', '\xda', '\xdb', '\xdc', '\xdd', '\xde', '\xff'
#endif /* (!(CHAR_MIN<0)) */
  };

const unsigned int NTL_char_attrib[] = {
#if (CHAR_MIN<0)
/* x80-x87 */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* x88-x8f */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* x90-x97 */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* x98-x9f */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* xa0-xa7 */ 0x0000, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* xa8-xaf */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* xb0-xb7 */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* xb8-xbf */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* xc0-xc7 */ 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00,
/* xc8-xcf */ 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00,
/* xd0-xd7 */ 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x0400,
/* xd8-xdf */ 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x0400,
/* xe0-xe7 */ 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
/* xe8-xef */ 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
/* xf0-xf7 */ 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x0400,
/* xf8-xff */ 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x0400
                ,
#endif /* (CHAR_MIN<0) */
/* x00-x07 */ 0x0404, 0x0404, 0x0404, 0x0404, 0x0404, 0x0404, 0x0404, 0x0004,
/* x08-x0f */ 0x0404, 0x0504, 0x10504, 0x0504, 0x0504, 0x10504, 0x0404, 0x0404,
/* x10-x17 */ 0x0404, 0x0404, 0x0404, 0x0404, 0x0404, 0x0404, 0x0404, 0x0404,
/* x18-x1f */ 0x0404, 0x0404, 0x0404, 0x0404, 0x0404, 0x0404, 0x0404, 0x0404,
/* ' '-x27 */ 0x0140, 0x04d0, 0x04d0, 0x04d0, 0x04d0, 0x04d0, 0x04d0, 0x24d0,
/* '('-'/' */ 0x04d0, 0x04d0, 0x04d0, 0x04d0, 0x00d0, 0x74d0, 0xe4d0, 0x04d0,
/* '0'-'7' */ 0xf459, 0xf459, 0xf459, 0xf459, 0xf459, 0xf459, 0xf459, 0xf459,
/* '8'-'?' */ 0xf459, 0xf459, 0x04d0, 0x04d0, 0x04d0, 0x04d0, 0x04d0, 0x04d0,
/* '@'-'G' */ 0x04d0, 0x7653, 0x7653, 0x7653, 0x7653, 0x7653, 0x7653, 0x7653,
/* 'H'-'O' */ 0x7653, 0x7653, 0x7653, 0x7653, 0x7653, 0x7653, 0x7653, 0x7653,
/* 'P'-'W' */ 0x7653, 0x7653, 0x7653, 0x7653, 0x7653, 0x7653, 0x7653, 0x7653,
/* 'X'-'_' */ 0x7653, 0x7653, 0x7653, 0x7653, 0x7653, 0x7653, 0x7653, 0x74d0,
/* '`'-'g' */ 0x34d0, 0x7473, 0x7473, 0x7473, 0x7473, 0x7473, 0x7473, 0x7473,
/* 'h'-'o' */ 0x7473, 0x7473, 0x7473, 0x7473, 0x7473, 0x7473, 0x7473, 0x7473,
/* 'p'-'w' */ 0x7473, 0x7473, 0x7473, 0x7473, 0x7473, 0x7473, 0x7473, 0x7473,
/* 'x'-x7f */ 0x7473, 0x7473, 0x7473, 0x7473, 0x7473, 0x7473, 0x7473, 0x0400
#if (!(CHAR_MIN<0))
                ,
/* x80-x87 */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* x88-x8f */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* x90-x97 */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* x98-x9f */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* xa0-xa7 */ 0x0000, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* xa8-xaf */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* xb0-xb7 */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* xb8-xbf */ 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400, 0x0400,
/* xc0-xc7 */ 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00,
/* xc8-xcf */ 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00,
/* xd0-xd7 */ 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x0400,
/* xd8-xdf */ 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x2c00, 0x0400,
/* xe0-xe7 */ 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
/* xe8-xef */ 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
/* xf0-xf7 */ 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x0400,
/* xf8-xff */ 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x0400
#endif /* (!(CHAR_MIN<0)) */
  };

/*
 * NTL_TOK_END
 * DO not touch anything above this line !
 */
/* *INDENT-ON* */

#endif /* !MAKETABLES */

/*=============================================================================
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

#ifdef MAKETABLES

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "common.h"

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

  markRange(NTL_IRCCH, 0, UCHAR_MAX);
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

  /* And finally let's take care of the toLower/toUpper stuff */

  setLowHi('a', 'z', 'A');
  setLowHi('\xe0', '\xf6', '\xc0');
  setLowHi('\xf8', '\xfe', '\xd8');
  setLowHi('{', '~', '[');

#ifndef FIXME			/* Just to remember that this is to be removed in u10.06 */
  setLowHi('\xd0', '\xd0', '\xd0');	/* Freeze the 0xD0 lower/upper */
  setLowHi('\xf0', '\xf0', '\xf0');	/* Freeze the 0xF0 lower/upper */
#endif /* FIXME */


}

/* 
 * main()
 * This is the main program to be executed for -DMAKETABLES
 */

static void dumphw(int *p, int beg);
static void dumphb(char *p, int beg);

int main(void)
{
  int i, j, k;
  char c, c1, c2;

  /* Make the tables */
  makeTables();

  /* Dump them as ANSI C source to be included below */

  /* NTL_tolower_tab */
  printf("const char NTL_tolower_tab[] = {\n");
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
  printf("const char NTL_toupper_tab[] = {\n");
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
  printf("const unsigned int NTL_char_attrib[] = {\n");
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
  };
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
    };
}

/* These are used in main() to actually dump the tables, each function
   dumps half table as hex/char constants... */

#define ROWSIZE 8

static void dumphb(char *tbl, int beg)
{
  int i, j, k, z;
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
    };
    printf("\n");
  };
}

static void dumphw(int *tbl, int beg)
{
  int i, j, k, z;
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
    };
    printf("\n");
  };
}

#endif /* MAKETABLES */
