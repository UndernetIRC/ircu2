/*
 * whocmds.h
 *
 * $Id$
 */
#ifndef INCLUDED_whocmds_h
#define INCLUDED_whocmds_h
#ifndef INCLUDED_config_h
#include "config.h"
#endif

struct Client;
struct Channel;


/*
 * m_who() 
 * m_who with support routines rewritten by Nemesi, August 1997
 * - Alghoritm have been flattened (no more recursive)
 * - Several bug fixes
 * - Strong performance improvement
 * - Added possibility to have specific fields in the output
 * See readme.who for further details.
 */

/* Macros used only in here by m_who and its support functions */

#define WHOSELECT_OPER 1
#define WHOSELECT_EXTRA 2

#define WHO_FIELD_QTY 1
#define WHO_FIELD_CHA 2
#define WHO_FIELD_UID 4
#define WHO_FIELD_NIP 8
#define WHO_FIELD_HOS 16
#define WHO_FIELD_SER 32
#define WHO_FIELD_NIC 64
#define WHO_FIELD_FLA 128
#define WHO_FIELD_DIS 256
#define WHO_FIELD_REN 512
#define WHO_FIELD_IDL 1024

#define WHO_FIELD_DEF ( WHO_FIELD_NIC | WHO_FIELD_UID | WHO_FIELD_HOS | WHO_FIELD_SER )

#define IS_VISIBLE_USER(s,ac) ((s==ac) || (!IsInvisible(ac)))

#if defined(SHOW_INVISIBLE_LUSERS) || defined(SHOW_ALL_INVISIBLE_USERS)
#define SEE_LUSER(s, ac, b) (IS_VISIBLE_USER(s, ac) || ((b & WHOSELECT_EXTRA) && MyConnect(ac) && IsAnOper(s)))
#else
#define SEE_LUSER(s, ac, b) (IS_VISIBLE_USER(s, ac))
#endif

#ifdef SHOW_ALL_INVISIBLE_USERS
#define SEE_USER(s, ac, b) (SEE_LUSER(s, ac, b) || ((b & WHOSELECT_EXTRA) && IsOper(s)))
#else
#define SEE_USER(s, ac, b) (SEE_LUSER(s, ac, b))
#endif

#ifdef UNLIMIT_OPER_QUERY
#define SHOW_MORE(sptr, counter) (IsAnOper(sptr) || (!(counter-- < 0)) )
#else
#define SHOW_MORE(sptr, counter) (!(counter-- < 0))
#endif

#ifdef OPERS_SEE_IN_SECRET_CHANNELS
#ifdef LOCOP_SEE_IN_SECRET_CHANNELS
#define SEE_CHANNEL(s, chptr, b) (!SecretChannel(chptr) || ((b & WHOSELECT_EXTRA) && IsAnOper(s)))
#else
#define SEE_CHANNEL(s, chptr, b) (!SecretChannel(chptr) || ((b & WHOSELECT_EXTRA) && IsOper(s)))
#endif
#else
#define SEE_CHANNEL(s, chptr, b) (!SecretChannel(chptr))
#endif

#define MAX_WHOIS_LINES 50

/*
 * Prototypes
 */
extern void do_who(struct Client* sptr, struct Client* acptr, struct Channel* repchan,
                   int fields, char* qrt);


#endif /* INCLUDED_whocmds_h */
