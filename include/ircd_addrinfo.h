#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

int irc_getaddrinfo(const char *hostname, const char *servname,
                    const struct addrinfo *hints, struct addrinfo **res);
int irc_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host,
                    size_t hostlen, char *serv, size_t servlen, int flags);
void irc_freeaddrinfo(struct addrinfo *ai);
