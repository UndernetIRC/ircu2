/*
 * IRC - Internet Relay Chat, ircd/hash.c
 * Copyright (C) 1998 Andrea Cocito, completely rewritten version.
 * Previous version was Copyright (C) 1991 Darren Reed, the concept
 * of linked lists for each hash bucket and the move-to-head 
 * optimization has been borrowed from there.
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

#include "sys.h"
#include <stdlib.h>
#include <limits.h>
#include "h.h"
#include "struct.h"
#include "common.h"
#include "hash.h"
#include "channel.h"
#include "send.h"
#include "s_serv.h"
#include "ircd.h"
#include "support.h"

RCSTAG_CC("$Id$");

/************************* Nemesi's hash alghoritm ***********************/

/* This hash function returns *exactly* N%HASHSIZE, where 'N'
 * is the string itself (included the trailing '\0') seen as 
 * a baseHASHSHIFT number whose "digits" are the bytes of the
 * number mapped through a "weight" transformation that gives
 * the same "weight" to caseless-equal chars, example:
 *
 * Hashing the string "Nick\0" the result will be:
 * N  i  c  k \0
 * |  |  |  |  `--->  ( (hash_weight('\0') * (HASHSHIFT**0) +
 * |  |  |  `------>    (hash_weight('k')  * (HASHSHIFT**1) +
 * |  |  `--------->    (hash_weight('c')  * (HASHSHIFT**2) +
 * |  `------------>    (hash_weight('i')  * (HASHSHIFT**3) +
 * `--------------->    (hash_weight('N')  * (HASHSHIFT**4)   ) % HASHSIZE
 *
 * It's actually a lot similar to a base transformation of the
 * text representation of an integer.
 * Looking at it this way seems slow and requiring unlimited integer
 * precision, but we actually do it with a *very* fast loop, using only 
 * short integer arithmetic and by means of two memory accesses and 
 * 3 additions per each byte processed.. and nothing else, as a side
 * note the distribution of real nicks over the hash table of this
 * function is about 3 times better than the previous one, and the
 * hash function itself is about 25% faster with a "normal" HASHSIZE
 * (it gets slower with larger ones and faster for smallest ones
 * because the hash table size affect the size of some maps and thus
 * the effectiveness of RAM caches while accesing them).
 * These two pages of macros are here to make the following code
 * _more_ understandeable... I hope ;)
 */

/* Internal stuff, think well before changing this, it's how
   much the weights of two lexicograhically contiguous chars 
   differ, i.e. (hash_weight('b')-hash_weight('a')) == HASHSTEP
   One seems to be fine but the alghoritm doesn't depend on it */
#define HASHSTEP 1

/* The smallest _prime_ int beeing HASHSTEP times bigger than a byte,
   that is the first prime bigger than the maximum hash_weight
   (since the maximum hash weight is gonne be the "biggest-byte * HASHSTEP") 
 */
#define HASHSHIFT 257

/* Are we sure that HASHSHIFT is big enough ? */
#if !(HASHSHIFT > (HASHSTEP*(CHAR_MAX-CHAR_MIN)))
#error "No no, I cannot, please make HASHSHIFT a bigger prime !"
#endif

/* Now HASHSIZE doesn't need to be a prime, but we really don't want it
   to be an exact multiple of HASHSHIFT, that would make the distribution
   a LOT worse, once is not multiple of HASHSHIFT it can be anything */
#if ((HASHSIZE%HASHSHIFT)==0)
#error "Please set HASHSIZE to something not multiple of HASHSHIFT"
#endif

/* What type of integer do we need in our computations ? the largest
   value we need to work on is (HASHSIZE+HASHSHIFT+1), for memory
   operations we want to keep the tables compact (the cache will work
   better and we will run faster) while for work variables we prefer
   to roundup to 'int' if it is the case: on platforms where int!=short
   int arithmetic is often faster than short arithmetic, we prefer signed
   types if they are big enough since on some architectures they are faster
   than unsigned, but we always keep signedness of mem and regs the same,
   to avoid sign conversions that sometimes require time, the following 
   precompile stuff will set HASHMEMS to an appropriate integer type for 
   the tables stored in memory and HASHREGS to an appropriate int type
   for the work registers/variables/return types. Everything of type
   HASH???S will remain internal to this source file so I placed this stuff
   here and not in the header file. */

#undef HASHMEMS
#undef HASHREGS

#if ((!defined(HASHMEMS)) && (HASHSIZE < (SHRT_MAX-HASHSHIFT)))
#define HASHMEMS short
#define HASHREGS int
#endif

#if ((!defined(HASHMEMS)) && (HASHSIZE < (USHRT_MAX-HASHSHIFT)))
#define HASHMEMS unsigned short
#define HASHREGS unsigned int
#endif

#if ((!defined(HASHMEMS)) && (HASHSIZE < (INT_MAX-HASHSHIFT)))
#define HASHMEMS int
#define HASHREGS int
#endif

#if ((!defined(HASHMEMS)) && (HASHSIZE < (UINT_MAX-HASHSHIFT)))
#define HASHMEMS unsigned int
#define HASHREGS unsigned int
#endif

#if ((!defined(HASHMEMS)) && (HASHSIZE < (LONG_MAX-HASHSHIFT)))
#define HASHMEMS long
#define HASHREGS long
#endif

#if ((!defined(HASHMEMS)) && (HASHSIZE < (ULONG_MAX-HASHSHIFT)))
#define HASHMEMS unsigned long
#define HASHREGS unsigned long
#endif

#if (!defined(HASHMEMS))
#error "Uh oh... I have a problem, do you want a 16GB hash table ? !"
#endif

/* Now we are sure that HASHMEMS and HASHREGS can contain the following */
#define HASHMAPSIZE (HASHSIZE+HASHSHIFT+1)

/* Static memory structures */

/* We need a first function that, given an integer h between 1 and
   HASHSIZE+HASHSHIFT, returns ( (h * HASHSHIFT) % HASHSIZE ) )
   We'll map this function in this table */
static HASHMEMS hash_map[HASHMAPSIZE];

/* Then we need a second function that "maps" a char to its weitgh,
   changed to a table this one too, with this macro we can use a char
   as index and not care if it is signed or not, no.. this will not
   cause an addition to take place at each access, trust me, the
   optimizer takes it out of the actual code and passes "label+shift"
   to the linker, and the linker does the addition :) */
static HASHMEMS hash_weight_table[CHAR_MAX - CHAR_MIN + 1];
#define hash_weight(ch) hash_weight_table[ch-CHAR_MIN]

/* The actual hash tables, both MUST be of the same HASHSIZE, variable
   size tables could be supported but the rehash routine should also
   rebuild the transformation maps, I kept the tables of equal size 
   so that I can use one hash function and one transformation map */
static aClient *clientTable[HASHSIZE];
static aChannel *channelTable[HASHSIZE];

/* This is what the hash function will consider "equal" chars, this function 
   MUST be transitive, if HASHEQ(y,x)&&HASHEQ(y,z) then HASHEQ(y,z), and MUST
   be symmetric, if HASHEQ(a,b) then HASHEQ(b,a), obvious ok but... :) */
#define HASHEQ(x,y) (((char) toLower((char) x)) == ((char) toLower((char) y)))

/* hash_init
 * Initialize the maps used by hash functions and clear the tables */
void hash_init(void)
{
  int i, j;
  unsigned long l, m;

  /* Clear the hash tables first */
  for (l = 0; l < HASHSIZE; l++)
  {
    channelTable[l] = (aChannel *)NULL;
    clientTable[l] = (aClient *)NULL;
  };

  /* Here is to what we "map" a char before working on it */
  for (i = CHAR_MIN; i <= CHAR_MAX; i++)
    hash_weight(i) = (HASHMEMS) (HASHSTEP * ((unsigned char)i));

  /* Make them equal for case-independently equal chars, it's
     lame to do it this way but I wanted the code flexible, it's
     possible to change the HASHEQ macro and not touch here. 
     I don't actually care about the 32768 loops since it happens 
     only once at startup */
  for (i = CHAR_MIN; i <= CHAR_MAX; i++)
    for (j = CHAR_MIN; j < i; j++)
      if (HASHEQ(i, j))
	hash_weight(i) = hash_weight(j);

  /* And this is our hash-loop "transformation" function, 
     basically it will be hash_map[x] == ((x*HASHSHIFT)%HASHSIZE)
     defined for 0<=x<=(HASHSIZE+HASHSHIFT) */
  for (m = 0; m < (unsigned long)HASHMAPSIZE; m++)
  {
    l = m;
    l *= (unsigned long)HASHSHIFT;
    l %= (unsigned long)HASHSIZE;
    hash_map[m] = (HASHMEMS) l;
  };
}

/* These are the actual hash functions, since they are static
   and very short any decent compiler at a good optimization level
   WILL inline these in the following functions */

/* This is the string hash function,
   WARNING: n must be a valid pointer to a _non-null_ string
   this means that not only strhash(NULL) but also
   strhash("") _will_ coredump, it's responsibility
   the caller to eventually check BadPtr(nick). */

static HASHREGS strhash(register char *n)
{
  register HASHREGS hash = hash_weight(*n++);
  while (*n)
    hash = hash_map[hash] + hash_weight(*n++);
  return hash_map[hash];
}

/* And this is the string hash function for limited lenght strings
   WARNING: n must be a valid pointer to a non-null string
   and i must be > 0 ! */

/* REMOVED

   The time taken to decrement i makes the function
   slower than strhash for the average of channel names (tested
   on 16000 real channel names, 1000 loops. I left the code here
   as a bookmark if a strnhash is evetually needed in the future.

   static HASHREGS strnhash(register char *n, register int i) {
   register HASHREGS hash = hash_weight(*n++);
   i--;
   while(*n && i--)
   hash = hash_map[hash] + hash_weight(*n++);
   return hash_map[hash];
   }

   #define CHANHASHLEN 30

   !REMOVED */

/************************** Externally visible functions ********************/

/* Optimization note: in these functions I supposed that the CSE optimization
 * (Common Subexpression Elimination) does its work decently, this means that
 * I avoided introducing new variables to do the work myself and I did let
 * the optimizer play with more free registers, actual tests proved this
 * solution to be faster than doing things like tmp2=tmp->hnext... and then
 * use tmp2 myself wich would have given less freedom to the optimizer.
 */

/*
 * hAddClient
 * Adds a client's name in the proper hash linked list, can't fail,
 * cptr must have a non-null name or expect a coredump, the name is
 * infact taken from cptr->name
 */
int hAddClient(aClient *cptr)
{
  register HASHREGS hashv = strhash(cptr->name);

  cptr->hnext = clientTable[hashv];
  clientTable[hashv] = cptr;

  return 0;
}

/*
 * hAddChannel
 * Adds a channel's name in the proper hash linked list, can't fail.
 * chptr must have a non-null name or expect a coredump.
 * As before the name is taken from chptr->name, we do hash its entire
 * lenght since this proved to be statistically faster
 */
int hAddChannel(aChannel *chptr)
{
  register HASHREGS hashv = strhash(chptr->chname);

  chptr->hnextch = channelTable[hashv];
  channelTable[hashv] = chptr;

  return 0;
}

/*
 * hRemClient
 * Removes a Client's name from the hash linked list
 */
int hRemClient(aClient *cptr)
{
  register HASHREGS hashv = strhash(cptr->name);
  register aClient *tmp = clientTable[hashv];

  if (tmp == cptr)
  {
    clientTable[hashv] = cptr->hnext;
    return 0;
  }
  while (tmp)
  {
    if (tmp->hnext == cptr)
    {
      tmp->hnext = tmp->hnext->hnext;
      return 0;
    }
    tmp = tmp->hnext;
  }
  return -1;
}

/*
 * hChangeClient
 * Removes the old name of a client from a linked list and adds
 * the new one to another linked list, there is a slight chanche
 * that this is useless if the two hashes are the same but it still
 * would need to move the name to the top of the list.
 * As always it's responsibility of the caller to check that
 * both newname and cptr->name are valid names (not "" or NULL).
 * Typically, to change the nick of an already hashed client:
 * if (!BadPtr(newname) && ClearTheNameSomeHow(newname)) {
 *   hChangeClient(cptr, newname);
 *   strcpy(cptr->name, newname);
 *   };
 * There isn't an equivalent function for channels since they
 * don't change name.
 */
int hChangeClient(aClient *cptr, char *newname)
{
  register HASHREGS newhash = strhash(newname);

  hRemClient(cptr);

  cptr->hnext = clientTable[newhash];
  clientTable[newhash] = cptr;
  return 0;
}

/*
 * hRemChannel
 * Removes the channel's name from the corresponding hash linked list
 */
int hRemChannel(aChannel *chptr)
{
  register HASHREGS hashv = strhash(chptr->chname);
  register aChannel *tmp = channelTable[hashv];

  if (tmp == chptr)
  {
    channelTable[hashv] = chptr->hnextch;
    return 0;
  };

  while (tmp)
  {
    if (tmp->hnextch == chptr)
    {
      tmp->hnextch = tmp->hnextch->hnextch;
      return 0;
    };
    tmp = tmp->hnextch;
  };

  return -1;
}

/*
 * hSeekClient
 * New semantics: finds a client whose name is 'name' and whose
 * status is one of those marked in TMask, if can't find one
 * returns NULL. If it finds one moves it to the top of the list
 * and returns it.
 */
aClient *hSeekClient(char *name, int TMask)
{
  register HASHREGS hashv = strhash(name);
  register aClient *cptr = clientTable[hashv];
  register aClient *prv;

  if (cptr)
    if ((!IsStatMask(cptr, TMask)) || strCasediff(name, cptr->name))
      while (prv = cptr, cptr = cptr->hnext)
	if (IsStatMask(cptr, TMask) && (!strCasediff(name, cptr->name)))
	{
	  prv->hnext = cptr->hnext;
	  cptr->hnext = clientTable[hashv];
	  clientTable[hashv] = cptr;
	  break;
	};

  return cptr;

}

/*
 * hSeekChannel
 * New semantics: finds a channel whose name is 'name', 
 * if can't find one returns NULL, if can find it moves
 * it to the top of the list and returns it.
 */
aChannel *hSeekChannel(char *name)
{
  register HASHREGS hashv = strhash(name);
  register aChannel *chptr = channelTable[hashv];
  register aChannel *prv;

  if (chptr)
    if (strCasediff(name, chptr->chname))
      while (prv = chptr, chptr = chptr->hnextch)
	if (!strCasediff(name, chptr->chname))
	{
	  prv->hnextch = chptr->hnextch;
	  chptr->hnextch = channelTable[hashv];
	  channelTable[hashv] = chptr;
	  break;
	};

  return chptr;

}

/* I will add some useful(?) statistics here one of these days,
   but not for DEBUGMODE: just to let the admins play with it,
   coders are able to SIGCORE the server and look into what goes
   on themselves :-) */

int m_hash(aClient *UNUSED(cptr), aClient *sptr, int UNUSED(parc), char *parv[])
{
  sendto_one(sptr, "NOTICE %s :SUSER SSERV", parv[0]);
  sendto_one(sptr, "NOTICE %s :SBSDC IRCDC", parv[0]);
  sendto_one(sptr, "NOTICE %s :CHANC SMISC", parv[0]);
  sendto_one(sptr, "NOTICE %s :HASHC VERSH", parv[0]);
  sendto_one(sptr, "NOTICE %s :MAKEF HOSTID", parv[0]);
  return 0;
}

/* Nick jupe utilities, these are in a static hash table with entry/bucket
   ratio of one, collision shift up and roll in a circular fashion, the 
   lowest 12 bits of the hash value are used, deletion is not supported,
   only addition, test for existence and cleanup of the table are.. */

#define JUPEHASHBITS 12		/* 4096 entries, 64 nick jupes allowed */
#define JUPEHASHSIZE (1<<JUPEHASHBITS)
#define JUPEHASHMASK (JUPEHASHSIZE-1)
#define JUPEMAX      (1<<(JUPEHASHBITS-6))

static char jupeTable[JUPEHASHSIZE][NICKLEN + 1];	/* About 40k */
static int jupesCount;

/*
 * isNickJuped()
 * Tells if a nick is juped (nonzero returned) or not (zero) 
 */
int isNickJuped(char *nick)
{
  register int pos;

  if (nick && *nick)
    for (pos = strhash(nick); (pos &= JUPEHASHMASK), jupeTable[pos][0]; pos++)
      if (!strCasediff(nick, jupeTable[pos]))
	return 1;
  return 0;			/* A bogus pointer is NOT a juped nick, right ? :) */
}

/*
 * addNickJupes()
 * Adds a (comma separated list of) nick jupes to the table 
 */
int addNickJupes(char *nicks)
{
  static char temp[512];
  char *one, *p;
  register int pos;

  if (nicks && *nicks)
  {
    strncpy(temp, nicks, 512);
    temp[512] = '\000';
    p = NULL;
    for (one = strtoken(&p, temp, ","); one; one = strtoken(&p, NULL, ","))
    {
      if (!*one)
	continue;
      pos = strhash(one);
    loop:
      pos &= JUPEHASHMASK;
      if (!jupeTable[pos][0])
      {
	if (jupesCount == JUPEMAX)
	  return 1;		/* Error: Jupe table is full ! */
	jupesCount++;
	strncpy(jupeTable[pos], one, NICKLEN);
	jupeTable[pos][NICKLEN] = '\000';	/* Better safe than sorry :) */
	continue;
      }
      if (!strCasediff(one, jupeTable[pos]))
	continue;
      ++pos;
      goto loop;
    }
  }
  return 0;
}

/*
 * clearNickJupes()
 * Cleans up the juped nicks table 
 */
void clearNickJupes(void)
{
  register int i;
  jupesCount = 0;
  for (i = 0; i < JUPEHASHSIZE; i++)
    jupeTable[i][0] = '\000';
}
