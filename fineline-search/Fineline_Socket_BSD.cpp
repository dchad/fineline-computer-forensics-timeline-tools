
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

#include "fineline-search.h"
#include "Fineline_Socket_BSD.h"

using namespace std;

Fineline_Socket_BSD::Fineline_Socket_BSD(string ip_addr, Fineline_Log &logger)
{
   cout << "GUI Address: " << ip_addr << endl;
   gui_ip_address = ip_addr;
   flog = logger;
}

Fineline_Socket_BSD::~Fineline_Socket_BSD()
{
   //dtor
}

#ifdef LINUX_BUILD

/*
   Function: open()
   Purpose : initialises and opens a POSIX socket.
   Input   : string containing the GUI IP address.
   Return  : A valid socket = success, -1 = fail.
*/
int Fineline_Socket_BSD::open_socket()
{
   struct sockaddr_in serv_addr;

   if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
   {
      flog.print_log_entry("init_socket() <ERROR> Could not create socket \n");
      return(-1);
   }

   memset(&serv_addr, '0', sizeof(serv_addr));

   serv_addr.sin_family = AF_INET;
   serv_addr.sin_port = htons(atoi(GUI_SERVER_PORT_STRING));

   if(inet_pton(AF_INET, gui_ip_address.c_str(), &serv_addr.sin_addr)<=0)
   {
      flog.print_log_entry("init_socket() <ERROR> inet_pton error occured\n");
      return(-1);
   }

   if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
   {
      flog.print_log_entry("init_socket() <ERROR> Connect Failed \n");
      return(-1);
   }

   return(0);
}

int Fineline_Socket_BSD::send_event(char *event_string)
{
   int k;

   k = send(sockfd, event_string, strlen(event_string), 0);
   if (k == -1)
   {
      flog.print_log_entry("send_event() <ERROR> Cannot send to server!\n");
   }

   return(k);
}

int Fineline_Socket_BSD::receive_message()
{
   return(0);
}

int Fineline_Socket_BSD::close_socket()
{
   close(sockfd);
   return(0);
}


#else

/* WINSOCK */

/*
   Function: open()
   Purpose : initialises a WINSOCK socket.
   Input   : string containing the GUI IP address.
   Return  : A valid socket = success, INVALID_SOCKET = fail.
*/
int Fineline_Socket_BSD::open_socket()
{
    WSADATA wsaData;
    struct addrinfo *resultaddrinfo = NULL, *ptr = NULL, hints;
    char *sendbuf = NULL;
    int result;

    result = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (result != 0)
	 {
        flog.print_log_entry("init_socket() <ERROR> WSAStartup failed with error.\n");
        return(-1);
    }

    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* Resolve the server address and port NOTE* getaddrinfo is in ws2_32.lib not in the old wsock32.lib */
    result = getaddrinfo(gui_ip_address, GUI_SERVER_PORT_STRING, &hints, &resultaddrinfo);
    if (result != 0)
    {
        flog.print_log_entry("init_socket() <ERROR> getaddrinfo failed with error.\n");
        WSACleanup();
        return(-1);
    }

    /* Attempt to connect to an address until one succeeds */
    for(ptr=resultaddrinfo; ptr != NULL ;ptr=ptr->ai_next)
    {

        /* Create a SOCKET for connecting to server */
        connect_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (connect_socket == INVALID_SOCKET)
        {
            flog.print_log_entry("init_socket() <ERROR> socket failed with error.\n");
            WSACleanup();
            return(INVALID_SOCKET);
        }

        /* Connect to server. */
        result = connect( connect_socket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (result == SOCKET_ERROR)
        {
            closesocket(connect_socket);
            connect_socket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(resultaddrinfo);

    if (connect_socket == INVALID_SOCKET)
    {
        flog.print_log_entry("init_socket() <ERROR> Unable to connect to server!\n");
        WSACleanup();
        return(-1);
    }

    return(0);

}


/*
   Function: send_event
   Purpose : sends the string to the GUI.
   Input   : socket, event record string.
   Return  : 0 = success, -1 = fail.
*/
int Fineline_Socket_BSD::send_event(char *event_string)
{
   int result;

    result = send(connect_socket, event_string, (int)strlen(event_string), 0);
    if (result == SOCKET_ERROR)
    {
        flog.print_log_entry("send_event() <ERROR> Send failed with error.\n");
        closesocket(connect_socket);
        WSACleanup();
        return(-1);
    }
	printf("send_event() <INFO> Sent event record %s\n", event_string);

	return(0);
}

/* TODO: acknowledge from server */
char *Fineline_Socket_BSD::receive_message()
{
   char *resp = (char *)xcalloc(FL_MAX_INPUT_STR);
   int result;

   result = recv(connect_socket, resp, FL_MAX_INPUT_STR, 0);
   if (result > 0)
        printf("get_response() <INFO> Bytes received: %d\n", result);
   else if (result == 0)
        printf("get_response() <ERROR> Connection closed\n");
   else
        printf("get_response() <ERROR> recv failed with error: %d\n", WSAGetLastError());

   return(resp);
}

int Fineline_Socket_BSD::close_socket()
{
   closesocket(connect_socket);
   WSACleanup();
   return(0);
}


#endif /* WINSOCK */

