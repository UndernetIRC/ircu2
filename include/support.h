/*
 * support.h
 *
 * $Id$
 */
#ifndef INCLUDED_support_h
#define INCLUDED_support_h
#ifndef INCLUDED_config_h
#include "config.h"
#define INCLUDED_config_h
#endif
#if 0
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>         /* broken BSD system headers */
#define INCLUDED_sys_types_h
#endif
#endif /* 0 */

/*
 * Prototypes
 */

extern void dumpcore(const char *pattern, ...);
extern int check_if_ipmask(const char *mask);
extern void write_log(const char *filename, const char *pattern, ...);

#endif /* INCLUDED_support_h */
