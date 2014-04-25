
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
   Fineline_Log.cpp

   Title : FineLine Computer Forensics File System Searcher
   Author: Derek Chadwick
   Date  : 24/04/2014

   Purpose: Implementation of a log file class.

*/

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <iostream>

using namespace std;

#include "fineline-search.h"
#include "Fineline_Log.h"

Fineline_Log::Fineline_Log()
{
   //ctor
}

Fineline_Log::Fineline_Log(string log_file_path)
{
   //ctor
}

Fineline_Log::~Fineline_Log()
{
   //dtor
}


/*
   Method  : open_log_file()

   Purpose : Opens the log file.
   Input   : Start file path.
   Output  : Returns log file pointer.
*/
int Fineline_Log::open_log_file()
{
	log_file = fopen(LOG_FILE, "a");

	if (log_file == NULL)
	{
	   printf("open_log_file() <ERROR>: could not open logfile: %s\n", LOG_FILE);
      return(-1);
	}

   return(0);
}


/*
   Method  : print_log_entry()

   Purpose : Creates a log entry and prints to the log file and stdin.
           :
   Input   : Log string.
   Output  : Timestamped log entry.
*/
int Fineline_Log::print_log_entry(char *estr)
{
   time_t curtime;
   struct tm *loctime;
   string log_entry;
   string time_str;

   /* Get the current time. */
   curtime = time (NULL);
   loctime = localtime (&curtime);
   time_str = asctime(loctime);
   log_entry = time_str;
   log_entry.append(" ");
   log_entry.append(estr);
   fputs (log_entry.c_str(), log_file);
   cout << log_entry << endl;

   return(0);
}

/*
   Method  : print_log_entry()

   Purpose : Creates a log entry and prints to the log file and stdin.
           :
   Input   : Log string.
   Output  : Timestamped log entry.
*/
int Fineline_Log::print_log_entry(string estr, int error_number)
{
   //TODO:

   return(0);
}

int Fineline_Log::close_log_file()
{

   if (log_file != NULL)
      fclose(log_file);

   return(0);
}

