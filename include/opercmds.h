/*
 * opercmds.h
 *
 * $Id$
 */
#ifndef INCLUDED_opercmds_h
#define INCLUDED_opercmds_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct Client;

/*
 * General defines
 */

/*-----------------------------------------------------------------------------
 * Macro's
 */
/*
 * Proto types
 */

extern void report_configured_links(struct Client* sptr, int mask);
extern char *militime(char* sec, char* usec);

#endif /* INCLUDED_opercmds_h */
