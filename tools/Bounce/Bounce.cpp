#include "Bounce.h"

/*
 *  Lacking Comments. :)
 *  12/04/2000 --Gte
 */

int main() {
  Bounce* application = new Bounce();

  /*
   *  Ignore SIGPIPE.
   */
  struct sigaction act; 
  act.sa_handler = SIG_IGN;
  act.sa_flags = 0;
  sigemptyset(&act.sa_mask);
  sigaction(SIGPIPE, &act, 0);

  /*
   *  Create new application object, bind listeners and begin
   *  polling them.
   */
  application->bindListeners();

  while (1) {
    application->checkSockets();
  } 
}

void Bounce::bindListeners() { 
  FILE* configFd;
  char tempBuf[256];
  int localPort = 0;
  int remotePort = 0;
  char* remoteServer;
  char* vHost; 
 
  /*
   *  Open config File.
   */
  
  if(!(configFd = fopen("bounce.conf", "r")))
  {
    printf("Error, unable to open config.\n");
    exit(0);
  } 

  while (fgets(tempBuf, 256, configFd) != NULL) { 
    if((tempBuf[0] != '#') && (tempBuf[0] != '\r')) {
    switch(tempBuf[0])
    {
      case 'P': { /* Add new port listener */ 
      strtok(tempBuf, ":");
      vHost = strtok(NULL, ":");
      localPort = atoi(strtok(NULL, ":"));
      remoteServer = strtok(NULL, ":");
      remotePort = atoi(strtok(NULL, ":")); 

      Listener* newListener = new Listener();
      strcpy(newListener->myVhost, vHost); 
      strcpy(newListener->remoteServer, remoteServer);
      newListener->remotePort = remotePort;
      newListener->localPort = localPort;
      printf("Adding new Listener: Local: %s:%i, Remote: %s:%i\n", vHost, localPort, remoteServer, remotePort);

      newListener->beginListening();
      listenerList.insert(listenerList.begin(), newListener); 
      break;
      }
    }
    } 
  } 
}

void Bounce::checkSockets() { 
/*
 *  Build up a Select FD set, and Select() 'em.
 */
  typedef std::list<Listener*> listenerContainer;
  typedef listenerContainer::iterator listIter;

  typedef std::list<Connection*> connectionContainer;
  typedef connectionContainer::iterator connIter; 

  struct timeval tv;
  fd_set readfds; 
  tv.tv_sec = 0;
  tv.tv_usec = 1000;
  int tempFd = 0;
  int tempFd2 = 0;
  int highestFd = 0;
  int delCheck = 0;
  char* tempBuf;

  FD_ZERO(&readfds);

  listIter a = listenerList.begin();
  while(a != listenerList.end())
  { 
    tempFd = (*a)->fd; 
    FD_SET(tempFd, &readfds);
    if (highestFd < tempFd) highestFd = tempFd;
    a++;
  }

  connIter b = connectionsList.begin();
  while(b != connectionsList.end())
  { 
    tempFd = (*b)->localSocket->fd;
    tempFd2 = (*b)->remoteSocket->fd;
    FD_SET(tempFd, &readfds);
    if (highestFd < tempFd) highestFd = tempFd;
    FD_SET(tempFd2, &readfds);
    if (highestFd < tempFd2) highestFd = tempFd2;
    b++;
  }

  select(highestFd+1, &readfds, NULL, NULL, &tv); 

  /*
   *  Check all connections for reading/writing
   *  First check Local FD's.
   */
  b = connectionsList.begin();
  while(b != connectionsList.end())
  { 
    tempFd = (*b)->localSocket->fd;
 
    if (FD_ISSET(tempFd, &readfds))
    { 
      tempBuf = (*b)->localSocket->read();
      if ((tempBuf[0] == 0)) // Connection closed on one of our sockets.
      {
        close((*b)->localSocket->fd);
        close((*b)->remoteSocket->fd); 
        printf("Closing FD: %i\n", (*b)->localSocket->fd);
        printf("Closing FD: %i\n", (*b)->remoteSocket->fd); 
        delete(*b);
        delCheck = 1;
        b = connectionsList.erase(b); 
      } else {
        (*b)->remoteSocket->write(tempBuf, (*b)->localSocket->lastReadSize); 
      }
    } 
 
  if (!delCheck) b++;
  delCheck = 0;
  } 

  /*
   *  Now check Remote FD's..
   */
  b = connectionsList.begin();
  while(b != connectionsList.end())
  { 
    tempFd = (*b)->remoteSocket->fd;
    if (FD_ISSET(tempFd, &readfds))
    {
      tempBuf = (*b)->remoteSocket->read();
      if ((tempBuf[0] == 0)) // Connection closed on one of our sockets.
      {
        close((*b)->localSocket->fd);
        close((*b)->remoteSocket->fd); 
        printf("Closing FD: %i\n", (*b)->localSocket->fd);
        printf("Closing FD: %i\n", (*b)->remoteSocket->fd);
        delete(*b);
        delCheck = 1;
        b = connectionsList.erase(b); 
      } else {
        (*b)->localSocket->write(tempBuf, (*b)->remoteSocket->lastReadSize);
      }
    }
  if (!delCheck) b++;
  delCheck = 0;
  } 
 
  /*
   *  Check all listeners for new connections.
   */
  a = listenerList.begin();
  while(a != listenerList.end())
  { 
    tempFd = (*a)->fd; 
    if (FD_ISSET(tempFd, &readfds))
    { 
      recieveNewConnection(*a);
    }
    a++;
  } 

}

void Bounce::recieveNewConnection(Listener* listener)
{
  Connection* newConnection = new Connection(); 
  newConnection->localSocket = listener->handleAccept();

  Socket* remoteSocket = new Socket();
  newConnection->remoteSocket = remoteSocket; 
  if(remoteSocket->connectTo(listener->remoteServer, listener->remotePort)) { 
    connectionsList.insert(connectionsList.begin(), newConnection);
  } else {
    newConnection->localSocket->write("Unable to connect to remote host..\n");
    close(newConnection->localSocket->fd);
    delete(newConnection);
    delete(remoteSocket);
  } 
}
 
 
Socket* Listener::handleAccept() {
  int new_fd = 0;
  int sin_size = sizeof(struct sockaddr_in);

  Socket* newSocket = new Socket();
  new_fd = accept(fd, (struct sockaddr*)&newSocket->address, (socklen_t*)&sin_size);
  newSocket->fd = new_fd; 
  return newSocket;
}
 
void Listener::beginListening() {
  struct sockaddr_in my_addr;
  int bindRes;
  int optval;
  optval = 1;

  fd = socket(AF_INET, SOCK_STREAM, 0); /* Check for no FD's left?! */

  my_addr.sin_family = AF_INET;
  my_addr.sin_port = htons(localPort);
  my_addr.sin_addr.s_addr = inet_addr(myVhost);
  bzero(&(my_addr.sin_zero), 8);

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  bindRes = bind(fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr));
  if(bindRes == 0)
  {
    listen(fd, 10);
  } else { 
     /*
      *  If we can't bind a listening port, we might aswell drop out.
      */
     printf("Unable to bind to %s:%i!\n", myVhost, localPort);
     exit(0);
   } 
}

Socket::Socket() {
  fd = -1;
  lastReadSize = 0;
}

int Socket::write(char *message, int len)
{ 
   if (fd == -1) return 0; 
 
   int amount = ::write(fd, message, len); 
   printf("Wrote %i Bytes.\n", amount);
   return amount; 
}

int Socket::write(char *message)
{ 
   if (fd == -1) return 0; 
 
   int amount = ::write(fd, message, strlen(message)); 
   printf("Wrote %i Bytes.\n", amount);
   return amount; 
}


int Socket::connectTo(char *hostname, unsigned short portnum) { 
  struct hostent     *hp;
 
  if ((hp = gethostbyname(hostname)) == NULL) { 
     return 0; 
  }          

  memset(&address,0,sizeof(address));
  memcpy((char *)&address.sin_addr,hp->h_addr,hp->h_length);
  address.sin_family= hp->h_addrtype;
  address.sin_port= htons((u_short)portnum);

  if ((fd = socket(hp->h_addrtype,SOCK_STREAM,0)) < 0)
    return 0; 
 
  if (connect(fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
    close(fd);
    fd = -1; 
    return 0;
  } 
  return(1);
}

char* Socket::read()
{ 
  int amountRead = 0;
  static char buffer[4096];

  amountRead = ::read(fd, &buffer, 4096);

  if ((amountRead == -1)) buffer[0] = '\0';
  buffer[amountRead] = '\0';

  printf("Read %i Bytes.\n", amountRead);
  /* Record this incase we're dealing with binary data with 0's in it. */
  lastReadSize = amountRead;
  return (char *)&buffer;
}
