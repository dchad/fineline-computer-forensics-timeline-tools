
/*  Copyright 2014 Derek Chadwick

    This file is part of the FineLine Computer Forensics Timeline Tools.

    FineLine is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    FineLine is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with FineLine.  If not, see <http://www.gnu.org/licenses/>.
*/


/*
   Fineline_Socket_BSD.cpp

   Title : FineLine Computer Forensics File System Searcher
   Author: Derek Chadwick
   Date  : 24/04/2014

   Purpose: Implementation of a POSIX/WIN32 socket class for communicating with the
            timeline GUI.

*/

#ifdef LINUX_BUILD

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

/* LINSOCK */
static int sockfd = 0;

#else

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/* WINSOCK */
static SOCKET connect_socket = INVALID_SOCKET;

#endif

#include <stdlib.h>
#include <stdio.h>
#include <iostream>

#include "Fineline_Socket_BSD.h"

Fineline_Socket_BSD::Fineline_Socket_BSD(string ip_addr, Fineline_Log &logger)
{
   cout << "Server Address: " << ip_addr << endl;
   flog = logger;
}

Fineline_Socket_BSD::~Fineline_Socket_BSD()
{
   //dtor
}

/*
   Function: open()
   Purpose : initialises and opens a POSIX socket.
   Input   : string containing the GUI IP address.
   Return  : A valid socket = success, -1 = fail.
*/
int Fineline_Socket_BSD::open()
{
   return(0);
}

int Fineline_Socket_BSD::send()
{
   return(0);
}

int Fineline_Socket_BSD::receive()
{
   return(0);
}

int Fineline_Socket_BSD::close()
{
   return(0);
}
