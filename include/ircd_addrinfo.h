#ifndef INCLUDED_config_h
#include "config.h"
#endif

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#ifndef INCLUDED_sys_socket_h
#include <sys/socket.h>
#define INCLUDED_sys_socket_h
#endif

#include <netdb.h>

#ifndef INCLUDED_netinet_in_h
#include <netinet/in.h>
#define INCLUDED_netinet_in_h
#endif

#ifdef HAVE_STDINT_H
#ifndef INCLUDED_stdint_h
#include <stdint.h>
#define INCLUDED_stdint_h
#endif
#endif

int irc_getaddrinfo(const char *hostname, const char *servname,
                    const struct addrinfo *hints, struct addrinfo **res);
int irc_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host,
                    size_t hostlen, char *serv, size_t servlen, int flags);
void irc_freeaddrinfo(struct addrinfo *ai);
