#ifndef S_DEBUG_H
#define S_DEBUG_H

#include <stdarg.h>
#ifdef MSGLOG_ENABLED
#include "struct.h"		/* Needed for HOSTLEN */
#endif

#ifdef DEBUGMODE

/*=============================================================================
 * Macro's
 */

#define Debug(x) debug x
#define LOGFILE LPATH

/*
 * defined debugging levels
 */
#define DEBUG_FATAL  0
#define DEBUG_ERROR  1		/* report_error() and other
				   errors that are found */
#define DEBUG_NOTICE 3
#define DEBUG_DNS    4		/* used by all DNS related routines - a *lot* */
#define DEBUG_INFO   5		/* general usful info */
#define DEBUG_NUM    6		/* numerics */
#define DEBUG_SEND   7		/* everything that is sent out */
#define DEBUG_DEBUG  8		/* anything to do with debugging,
				   ie unimportant :) */
#define DEBUG_MALLOC 9		/* malloc/free calls */
#define DEBUG_LIST  10		/* debug list use */

/*=============================================================================
 * proto types
 */

extern void vdebug(int level, const char *form, va_list vl);
extern void debug(int level, const char *form, ...)
    __attribute__ ((format(printf, 2, 3)));
extern void send_usage(aClient *cptr, char *nick);

#else /* !DEBUGMODE */

#define Debug(x)
#define LOGFILE "/dev/null"

#endif /* !DEBUGMODE */

extern void count_memory(aClient *cptr, char *nick);
extern char serveropts[];

/*=============================================================================
 * Message logging service
 */

/*
 * Message levels: these are inclusive, i.e. a message that is LEVEL_MAP
 * affects also clients and channels and is propagated and needs a query of
 * some status, and therefore belongs to all the classes, in the same way
 * _every_ message is parsed so belongs to LEVEL_PARSED
 */

/* Messages that affect servers' map */
#define LEVEL_MAP	6

/* Messages that affect clients existance */
#define LEVEL_CLIENT	5

/* Messages that affect channel existance */
#define LEVEL_CHANNEL	4

/* Messages that affect channel modes */
#define LEVEL_MODE	3

/* Messages that are only to be propagated somewhere */
#define LEVEL_PROPAGATE 2

/*
 * Messages that only perform queries
 * note how every message may need some status query over data structs
 * and at the same time every query might need to be propagated
 * somewhere... so the distinction between levels PROPAGATE and
 * QUERY is quite fuzzy
 */
#define LEVEL_QUERY	1

/* Messages that only perform queries */
#define LEVEL_PARSED	0

#ifdef MSGLOG_ENABLED

/*=============================================================================
 * Macro's
 */

#define LogMessage(x) Log_Message x
#define StoreBuffer(x) Store_Buffer x

/* Logging mask, selection on type of connection */
#define LOG_PING	(0x8000 >> (8 + STAT_PING))
#define LOG_LOG		(0x8000 >> (8 + STAT_LOG))
#define LOG_CONNECTING	(0x8000 >> (8 + STAT_CONNECTING))
#define LOG_HANDSHAKE	(0x8000 >> (8 + STAT_HANDSHAKE))
#define LOG_ME		(0x8000 >> (8 + STAT_ME))
#define LOG_UNKNOWN	(0x8000 >> (8 + STAT_UNKNOWN))
#define LOG_SERVER	(0x8000 >> (8 + STAT_SERVER))
#define LOG_CLIENT	(0x8000 >> (8 + STAT_USER))

/*
 * Define here the type of connection(s) that will be monitored.
 * Default is to log messages coming from any connection.
 */
#define LOG_MASK_TYPE \
    ( LOG_PING | LOG_LOG | LOG_CONNECTING | \
      LOG_HANDSHAKE | LOG_ME | LOG_UNKNOWN | LOG_SERVER | LOG_CLIENT )

/*=============================================================================
 * data structures
 */

struct log_entry {
  int cptr_status;
  char cptr_name[HOSTLEN + 1];
  char cptr_yxx[3];
  int cptr_fd;

  int sptr_status;
  char sptr_name[HOSTLEN + 1];
  char sptr_yxx[4];
  char sptr_from_name[HOSTLEN + 1];

  char buffer[512];

  /* The following may be lost before log gets used,
     anyhow they are only here for usage through gdb */

  aClient *cptr;
  aClient *sptr;
};

/*=============================================================================
 * proto types
 */

extern void Log_Message(aClient *sptr, int msgclass);
extern void Store_Buffer(char *buf, aClient *cptr);

#else /* !MSGLOG_ENABLED */

#define LogMessage(x)
#define StoreBuffer(x)

#endif /* !MSGLOG_ENABLED */

#endif /* S_DEBUG_H */
