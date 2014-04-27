
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
   fllog.c

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 22/12/2013

   Purpose: Logging, reporting and debug functions.

*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "fineline-ws.h"

static FILE *log_file;

/*
   Function: open_log_file()

   Purpose : Opens the log file.
   Input   : Start file path.
   Output  : Returns log file pointer.
*/
int open_log_file(char *startup_path)
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
   Function: print_log_entry()

   Purpose : Creates a log entry and prints to the log file and stdin.
           :
   Input   : Log string.
   Output  : Timestamped log entry.
*/
int print_log_entry(char *estr)
{
   time_t curtime;
   struct tm *loctime;
   int slen = strlen(estr);
   char *log_entry = (char *)xcalloc(slen + 100);
   char *time_str;

   /* Get the current time. */
   curtime = time (NULL);
   loctime = localtime (&curtime);
   time_str = asctime(loctime);
   strncpy(log_entry, time_str, strlen(time_str) - 1);
   strncat(log_entry, " ", 1);
   strncat(log_entry, estr, slen);
   fputs (log_entry, log_file);
   printf("%s", log_entry);

   xfree(log_entry, slen + 100);

   return(0);
}

int close_log_file()
{

   if (log_file != NULL)
      fclose(log_file);

   return(0);
}
