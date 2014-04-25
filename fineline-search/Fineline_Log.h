
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
   Fineline_Log.h

   Title : FineLine Computer Forensics File System Searcher
   Author: Derek Chadwick
   Date  : 24/04/2014

   Purpose: Definition of a log file class.

*/


#ifndef FINELINE_LOG_H
#define FINELINE_LOG_H

#include <stdio.h>
#include <string>

using namespace std;

class Fineline_Log
{
   public:
      Fineline_Log();
      Fineline_Log(string log_file_path);
      virtual ~Fineline_Log();

      int open_log_file();
      int print_log_entry(char *estr);
      int print_log_entry(string estr, int error_number);
      int close_log_file();

   protected:
   private:

      FILE *log_file;
};

#endif // FINELINE_LOG_H
