#include <sys/types.h> 
#include <sys/time.h>
#include <sys/wait.h> 
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <ctype.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <string.h> 
#include <netdb.h> 
#include <ctype.h>
#include <time.h>
#include <list>
using std::list; 


/*
 *  "Bounce" Class.
 */

class Listener;
class Connection;
class Bounce
{
public:
  list<Listener*> listenerList; // List of Listeners.
  list<Connection*> connectionsList; // List of 'Connections'. 

  void bindListeners(); //Binds Listening Ports.
  void checkSockets(); // Polls all sockets.
  void recieveNewConnection(Listener*);
};

/*
 *  "Socket" Class.
 */

class Socket 
{
public:
  int fd; 
  int lastReadSize;
  struct sockaddr_in address;
  int connectTo(char*, unsigned short);
  int write(char*, int); 
  int write(char*); 
  char* read();
  Socket();
};

/*
 *  "Listener" Class.
 */

class Bounce;
class Listener
{
public:
  int fd; 
  int remotePort;
  int localPort;
  char myVhost[15];
  char remoteServer[15];

  void beginListening();
  Socket* handleAccept();
};

/*
 *  "Connection" Class.
 */

class Connection 
{ 
public:
  Socket* localSocket;
  Socket* remoteSocket;
};

