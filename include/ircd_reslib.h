/*
 * include/ircd_reslib.h
 * (C)opyright 1992 Darren Reed.
 */
/** @file
 * @brief Interface from ircd resolver to its support functions.
 * @version $Id$
 */
#ifndef INCLUDED_ircdreslib_h
#define INCLUDED_ircdreslib_h

#include <netdb.h>

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 */
/** Get a 16-bit network endian value from \a cp and assign to \a s. */
#define IRC_NS_GET16(s, cp) { \
	const unsigned char *t_cp = (const unsigned char *)(cp); \
	(s) = ((uint16_t)t_cp[0] << 8) \
	    | ((uint16_t)t_cp[1]) \
	    ; \
	(cp) += NS_INT16SZ; \
}

/** Get a 32-bit network endian value from \a cp and assign to \a s. */
#define IRC_NS_GET32(l, cp) { \
	const unsigned char *t_cp = (const unsigned char *)(cp); \
	(l) = ((uint32_t)t_cp[0] << 24) \
	    | ((uint32_t)t_cp[1] << 16) \
	    | ((uint32_t)t_cp[2] << 8) \
	    | ((uint32_t)t_cp[3]) \
	    ; \
	(cp) += NS_INT32SZ; \
}

/** Put \a s at \a cp as a 16-bit network endian value. */
#define IRC_NS_PUT16(s, cp) { \
	uint16_t t_s = (uint16_t)(s); \
	unsigned char *t_cp = (unsigned char *)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += NS_INT16SZ; \
}

/** Put \a s at \a cp as a 32-bit network endian value. */
#define IRC_NS_PUT32(l, cp) { \
	uint32_t t_l = (uint32_t)(l); \
	unsigned char *t_cp = (unsigned char *)(cp); \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp   = t_l; \
	(cp) += NS_INT32SZ; \
}

/** Maximum number of nameservers to bother with. */
#define IRCD_MAXNS 8

int irc_res_init(void);
int irc_dn_expand(const unsigned char *msg, const unsigned char *eom, const unsigned char *src, char *dst, int dstsiz);
int irc_ns_name_uncompress(const unsigned char *msg, const unsigned char *eom, const unsigned char *src, char *dst, size_t dstsiz);
int irc_ns_name_unpack(const unsigned char *msg, const unsigned char *eom, const unsigned char *src, unsigned char *dst, size_t dstsiz);
int irc_ns_name_ntop(const char *src, char *dst, size_t dstsiz);
int irc_dn_comp(const char *src, unsigned char *dst, int dstsiz, unsigned char **dnptrs, unsigned char **lastdnptr);
int irc_dn_skipname(const unsigned char *ptr, const unsigned char *eom);
int irc_ns_name_skip(const unsigned char **ptrptr, const unsigned char *eom);
unsigned int irc_ns_get16(const unsigned char *src);
unsigned long irc_ns_get32(const unsigned char *src);
void irc_ns_put16(unsigned int src, unsigned char *dst);
void irc_ns_put32(unsigned long src, unsigned char *dst);
int irc_ns_name_pton(const char *src, unsigned char *dst, size_t dstsiz);
int irc_ns_name_pack(const unsigned char *src, unsigned char *dst, int dstsiz, const unsigned char **dnptrs, const unsigned char **lastdnptr);
int irc_res_mkquery(const char *dname, int class, int type, unsigned char *buf, int buflen);
#endif /* INCLUDED_res_h */
