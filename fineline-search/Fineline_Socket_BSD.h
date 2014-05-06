
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
   Fineline_Socket_BSD.h

   Title : FineLine Computer Forensics File System Searcher
   Author: Derek Chadwick
   Date  : 24/04/2014

   Purpose: Definition of a POSIX/WIN32 socket for communicating with the
            timeline GUI.

*/


#ifndef FINELINE_SOCKET_BSD_CPP_H
#define FINELINE_SOCKET_BSD_CPP_H

using namespace std;

#include <string>

#include "Fineline_Log.h"
#include "Fineline_Util.h"

class Fineline_Socket_BSD
{
   public:
      Fineline_Socket_BSD(string ip_addr, Fineline_Log &logger);
      virtual ~Fineline_Socket_BSD();

      int open_socket();
      int close_socket();
      int send_event(char *event_string);
      char *receive_message();

   protected:
   private:
      Fineline_Log flog;
	  Fineline_Util flut;
      string gui_ip_address;
};

#endif // FINELINE_SOCKET_BSD_CPP_H
