#ifndef PACKET_H
#define PACKET_H

/*=============================================================================
 * Proto types
 */

extern int dopacket(aClient *cptr, char *buffer, int length);
extern int client_dopacket(aClient *cptr, size_t length);

#endif /* PACKET_H */
