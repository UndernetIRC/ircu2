/** @file s_user.h
 * @brief Miscellaneous user-related helper functions.
 * @version $Id$
 */
#ifndef INCLUDED_s_user_h
#define INCLUDED_s_user_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct Client;
struct User;
struct Channel;
struct MsgBuf;
struct Flags;

/*
 * Macros
 */

/**
 * Nick flood limit.
 * Minimum time between nick changes.
 * (The first two changes are allowed quickly after another however).
 */
#define NICK_DELAY 30

/**
 * Target flood time.
 * Minimum time between target changes.
 * (MAXTARGETS are allowed simultaneously however).
 * Its set to a power of 2 because we devide through it quite a lot.
 */
#define TARGET_DELAY 128

/* return values for hunt_server() */

#define HUNTED_NOSUCH   (-1)    /**< if the hunted server is not found */
#define HUNTED_ISME     0       /**< if this server should execute the command */
#define HUNTED_PASS     1       /**< if message passed onwards successfully */

/* send sets for send_umode() */
#define ALL_UMODES 0  /**< both local and global user modes */
#define SEND_UMODES 1  /**< global user modes only */
#define SEND_UMODES_BUT_OPER 2  /**< global user modes except for FLAG_OPER */

/* used when sending to #mask or $mask */

#define MATCH_SERVER  1 /**< flag for relay_masked_message (etc) to indicate the mask matches a server name */
#define MATCH_HOST    2 /**< flag for relay_masked_message (etc) to indicate the mask matches host name */

/* used for parsing user modes */
#define ALLOWMODES_ANY	0 /**< Allow any user mode */
#define ALLOWMODES_DEFAULT  1 /**< Only allow the subset of modes that are legit defaults */

/** Formatter function for send_user_info().
 * @param who Client being displayed.
 * @param sptr Client requesting information.
 * @param buf Message buffer that should receive the response text.
 */
typedef void (*InfoFormatter)(struct Client* who, struct Client *sptr, struct MsgBuf* buf);

/*
 * Prototypes
 */
extern struct User* make_user(struct Client *cptr);
extern void         free_user(struct User *user);
extern int          register_user(struct Client* cptr, struct Client *sptr);

extern void         user_count_memory(size_t* count_out, size_t* bytes_out);

extern int set_nick_name(struct Client* cptr, struct Client* sptr,
                         const char* nick, int parc, char* parv[]);
extern void send_umode_out(struct Client* cptr, struct Client* sptr,
                          struct Flags* old, int prop);
extern void send_umode(struct Client *cptr, struct Client *sptr, struct Flags *old,
                       int sendset);
extern int whisper(struct Client* source, const char* nick,
                   const char* channel, const char* text, int is_notice);
extern void send_user_info(struct Client* to, char* names, int rpl,
                           InfoFormatter fmt);

extern int hide_hostmask(struct Client *cptr, unsigned int flags);
extern int set_user_mode(struct Client *cptr, struct Client *sptr,
                         int parc, char *parv[], int allow_modes);
extern int is_silenced(struct Client *sptr, struct Client *acptr);
extern int hunt_server_cmd(struct Client *from, const char *cmd,
			   const char *tok, struct Client *one,
			   int MustBeOper, const char *pattern, int server,
			   int parc, char *parv[]);
extern int hunt_server_prio_cmd(struct Client *from, const char *cmd,
				const char *tok, struct Client *one,
				int MustBeOper, const char *pattern,
				int server, int parc, char *parv[]);
extern struct Client* next_client(struct Client* next, const char* ch);
extern char *umode_str(struct Client *cptr);
extern void send_umode(struct Client *cptr, struct Client *sptr,
                       struct Flags *old, int sendset);
extern void set_snomask(struct Client *, unsigned int, int);
extern int is_snomask(char *);
extern int check_target_limit(struct Client *sptr, void *target, const char *name,
    int created);
extern void add_target(struct Client *sptr, void *target);
extern unsigned int umode_make_snomask(unsigned int oldmask, char *arg,
                                       int what);
extern int send_supported(struct Client *cptr);

#define NAMES_ALL 1 /**< List all users in channel */
#define NAMES_VIS 2 /**< List only visible users in non-secret channels */
#define NAMES_EON 4 /**< Add an 'End Of Names' reply to the end */
#define NAMES_DEL 8 /**< Show delayed joined users only */

void do_names(struct Client* sptr, struct Channel* chptr, int filter);

#endif /* INCLUDED_s_user_h */
