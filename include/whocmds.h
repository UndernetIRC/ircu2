/*
 * whocmds.h
 *
 * $Id$
 */
#ifndef INCLUDED_whocmds_h
#define INCLUDED_whocmds_h

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
#define WHO_FIELD_ACC 2048

#define WHO_FIELD_DEF ( WHO_FIELD_NIC | WHO_FIELD_UID | WHO_FIELD_HOS | WHO_FIELD_SER )

#define IS_VISIBLE_USER(s,ac) ((s==ac) || (!IsInvisible(ac)))

#define SEE_LUSER(s, ac, b) (IS_VISIBLE_USER(s, ac) || ((b & WHOSELECT_EXTRA) && MyConnect(ac) && (HasPriv((s), PRIV_SHOW_INVIS) || HasPriv((s), PRIV_SHOW_ALL_INVIS))))

#define SEE_USER(s, ac, b) (SEE_LUSER(s, ac, b) || ((b & WHOSELECT_EXTRA) && HasPriv((s), PRIV_SHOW_ALL_INVIS)))

#define SHOW_MORE(sptr, counter) (HasPriv(sptr, PRIV_UNLIMIT_QUERY) || (!(counter-- < 0)) )

#define SEE_CHANNEL(s, chptr, b) (!SecretChannel(chptr) || ((b & WHOSELECT_EXTRA) && HasPriv((s), PRIV_SEE_CHAN)))

#define MAX_WHOIS_LINES 50

/*
 * Prototypes
 */
extern void do_who(struct Client* sptr, struct Client* acptr, struct Channel* repchan,
                   int fields, char* qrt);
extern int count_users(char* mask);

#endif /* INCLUDED_whocmds_h */
