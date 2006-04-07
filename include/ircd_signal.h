/** @file ircd_signal.h
 * @brief Interface to signal handler subsystem.
 * @version $Id$
 */
#ifndef INCLUDED_ircd_signal_h
#define INCLUDED_ircd_signal_h

typedef void (*SigChldCallBack)(pid_t child_pid, void *datum, int status);

extern void setup_signals(void);
extern void register_child(pid_t child, SigChldCallBack call, void *datum);
extern void unregister_child(pid_t child);
extern void reap_children(void);

#endif /* INCLUDED_ircd_signal_h */

