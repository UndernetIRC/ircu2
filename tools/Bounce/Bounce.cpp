/*
 * IRC - Internet Relay Chat, tools/Bounce/Bounce.cpp
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Port Bouncer.
 *
 * This tool is designed to set up a number of local listening ports, and
 * then forward any data recived on those ports, to another host/port combo.
 * Each listening port can bounce to a different host/port defined in the
 * config file. --Gte 
 *
 * $Id: Bounce.cpp,v 1.3 2002-03-07 22:52:57 ghostwolf Exp $ 
 *
 */

#include "Bounce.h"
 
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
 
#ifndef DEBUG
  /*
   *  If we aren't debugging, we might as well
   *  detach from the console.
   */

  pid_t forkResult = fork() ;
  if(forkResult < 0)
  { 
    printf("Unable to fork new process.\n");
    return -1 ;
  } 
  else if(forkResult != 0)
  {
    printf("Successfully Forked, New process ID is %i.\n", forkResult);
    return 0;
  } 
#endif

  /*
   *  Create new application object, bind listeners and begin
   *  polling them.
   */
  application->bindListeners();

  while (1) {
    application->checkSockets();
  } 
}

/*
 ****************************************
 *                                      *
 *     Bounce class implementation.     *
 *                                      *
 ****************************************
 */
 
void Bounce::bindListeners() { 
/*
 *  bindListeners.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: 1. Reads the config file, and..
 *           2. Creates a new listener for each 'P' line found.
 *
 */

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
    printf("Error, unable to open config file!\n");
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
#ifdef DEBUG
        printf("Adding new Listener: Local: %s:%i, Remote: %s:%i\n", vHost, localPort, remoteServer, remotePort);
#endif

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
 *  checkSockets.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: 1. Builds up a FD_SET of all sockets we wish to check.
 *              (Including all listeners & all open connections).
 *           2. SELECT(2) the set, and forward/accept as needed.
 *
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
 
  /*
   *  Add all Listeners to the set.
   */

  listIter a = listenerList.begin();
  while(a != listenerList.end())
  { 
    tempFd = (*a)->fd; 
    FD_SET(tempFd, &readfds);
    if (highestFd < tempFd) highestFd = tempFd;
    a++;
  }

  /*
   *  Add Local & Remote connections from each
   *  connection object to the set.
   */

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
   *  Check all connections for readability.
   *  First check Local FD's.
   *  If the connection is closed on either side,
   *  shutdown both sockets, and clean up.
   *  Otherwise, send the data from local->remote, or
   *  remote->local.
   */

  b = connectionsList.begin();
  while(b != connectionsList.end())
  { 
    tempFd = (*b)->localSocket->fd;
 
    if (FD_ISSET(tempFd, &readfds))
    { 
      tempBuf = (*b)->localSocket->read();
      if ((tempBuf[0] == 0)) // Connection closed.
      {
        close((*b)->localSocket->fd);
        close((*b)->remoteSocket->fd); 
#ifdef DEBUG
        printf("Closing FD: %i\n", (*b)->localSocket->fd);
        printf("Closing FD: %i\n", (*b)->remoteSocket->fd); 
#endif
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
      if ((tempBuf[0] == 0)) // Connection closed.
      {
        close((*b)->localSocket->fd);
        close((*b)->remoteSocket->fd); 
#ifdef DEBUG
        printf("Closing FD: %i\n", (*b)->localSocket->fd);
        printf("Closing FD: %i\n", (*b)->remoteSocket->fd);
#endif
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

void Bounce::recieveNewConnection(Listener* listener) {
/*
 *  recieveNewConnection.
 *  Inputs: A Listener Object.
 *  Outputs: Nothing.
 *  Process: 1. Recieves a new connection on a local port,
 *              and creates a connection object for it.
 *           2. Accepts the incomming connection.
 *           3. Creates a new Socket object for the remote
 *              end of the connection.
 *           4. Connects up the remote Socket.
 *           5. Adds the new Connection object to the
 *              connections list.
 *
 */

  Connection* newConnection = new Connection(); 
  newConnection->localSocket = listener->handleAccept();

  Socket* remoteSocket = new Socket();
  newConnection->remoteSocket = remoteSocket; 
  if(remoteSocket->connectTo(listener->remoteServer, listener->remotePort)) { 
    connectionsList.insert(connectionsList.begin(), newConnection);
  } else {
#ifdef DEBUG
    newConnection->localSocket->write("Unable to connect to remote host.\n");
#endif
    close(newConnection->localSocket->fd);
    delete(newConnection);
    delete(remoteSocket);
  } 
}
 

/*
 ****************************************
 *                                      *
 *    Listener class implementation.    *
 *                                      *
 ****************************************
 */

 
Socket* Listener::handleAccept() {
/*
 *  handleAccept.
 *  Inputs: Nothing.
 *  Outputs: A Socket Object.
 *  Process: 1. Accept's an incomming connection,
 *              and returns a new socket object. 
 */

  int new_fd = 0;
  int sin_size = sizeof(struct sockaddr_in);

  Socket* newSocket = new Socket();
  new_fd = accept(fd, (struct sockaddr*)&newSocket->address, (socklen_t*)&sin_size);
  newSocket->fd = new_fd; 
  return newSocket;
}
 
void Listener::beginListening() {
/*
 *  beginListening.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: 1. Binds the local ports for all the
 *              Listener objects.
 *
 */

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

/*
 ****************************************
 *                                      *
 *     Socket class implementation.     *
 *                                      *
 ****************************************
 */


Socket::Socket() {
/*
 *  Socket Constructor.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: Initialises member variables.
 *
 */

  fd = -1;
  lastReadSize = 0;
}

int Socket::write(char *message, int len) { 
/*
 *  write.
 *  Inputs: Message string, and lenght.
 *  Outputs: Amount written, or 0 on error.
 *  Process: 1. Writes out 'len' amount of 'message'.
 *              to this socket.
 *
 */

   if (fd == -1) return 0; 
 
   int amount = ::write(fd, message, len); 
#ifdef DEBUG
   printf("Wrote %i Bytes.\n", amount);
#endif
   return amount; 
}

int Socket::write(char *message) { 
/*
 *  write(2).
 *  Inputs: Message string.
 *  Outputs: Amount writte, or 0 on error.
 *  Process: Writes out the whole of 'message'.
 *
 */

   if (fd == -1) return 0; 
 
   int amount = ::write(fd, message, strlen(message)); 
#ifdef DEBUG
   printf("Wrote %i Bytes.\n", amount);
#endif
   return amount; 
}


int Socket::connectTo(char *hostname, unsigned short portnum) { 
/*
 *  connectTo.
 *  Inputs: Hostname and port.
 *  Outputs: +ve on success, 0 on failure.
 *  Process: 1. Connects this socket to remote 'hostname' on
 *              port 'port'.
 *
 */

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

char* Socket::read() { 
/*
 *  read.
 *  Inputs: Nothing.
 *  Outputs: char* to static buffer containing data.
 *  Process: 1. Reads as much as possible from this socket, up to
 *              4k.
 *
 */

  int amountRead = 0;
  static char buffer[4096];

  amountRead = ::read(fd, &buffer, 4096);

  if ((amountRead == -1)) buffer[0] = '\0';
  buffer[amountRead] = '\0';

#ifdef DEBUG
  printf("Read %i Bytes.\n", amountRead);
#endif
 
  /* 
   * Record this just incase we're dealing with binary data with 0's in it.
   */
  lastReadSize = amountRead;
  return (char *)&buffer;
}

