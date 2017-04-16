/** @file ircd_osdep.h
 * @brief Public definitions and APIs for OS-dependent operations.
 * @version $Id$
 */
#ifndef INCLUDED_ircd_osdep_h
#define INCLUDED_ircd_osdep_h

struct Client;
struct irc_sockaddr;
struct MsgQ;

/** Result of an input/output operation. */
typedef enum IOResult {
  IO_FAILURE = -1, /**< Serious I/O error (not due to blocking). */
  IO_BLOCKED = 0,  /**< I/O could not start because it would block. */
  IO_SUCCESS = 1   /**< I/O succeeded. */
} IOResult;

/*
 * NOTE: osdep.c files should never need to know the actual size of a
 * Client struct. When passed as a parameter, the pointer just needs
 * to be forwarded to the enumeration function.
 */
/** Callback function to show rusage information.
 * @param cptr Client to receive the message.
 * @param msg Text message to send to user.
 */
typedef void (*EnumFn)(struct Client* cptr, const char* msg);

extern int os_disable_options(int fd);
extern int os_get_rusage(struct Client* cptr, int uptime, EnumFn enumerator);
extern int os_get_sockerr(int fd);
extern int os_get_sockname(int fd, struct irc_sockaddr* sin_out);
extern int os_get_peername(int fd, struct irc_sockaddr* sin_out);
extern int os_socket(const struct irc_sockaddr* local, int type, const char* port_name, int family);
extern int os_accept(int fd, struct irc_sockaddr* peer);
extern IOResult os_sendto_nonb(int fd, const char* buf, unsigned int length,
                               unsigned int* length_out, unsigned int flags,
                               const struct irc_sockaddr* peer);
extern IOResult os_recv_nonb(int fd, char* buf, unsigned int length,
                        unsigned int* length_out);
extern IOResult os_send_nonb(int fd, const char* buf, unsigned int length,
                        unsigned int* length_out);
extern IOResult os_sendv_nonb(int fd, struct MsgQ* buf,
			      unsigned int* len_in, unsigned int* len_out);
extern IOResult os_recvfrom_nonb(int fd, char* buf, unsigned int len,
                                 unsigned int* length_out,
                                 struct irc_sockaddr* from_out);
extern IOResult os_connect_nonb(int fd, const struct irc_sockaddr* sin);
extern int os_set_fdlimit(unsigned int max_descriptors);
extern int os_set_listen(int fd, int backlog);
extern int os_set_nonblocking(int fd);
extern int os_set_reuseaddr(int fd);
extern int os_set_sockbufs(int fd, unsigned int ssize, unsigned int rsize);
extern int os_set_tos(int fd, int tos, int family);
extern int os_socketpair(int sv[2]);

#endif /* INCLUDED_ircd_osdep_h */

