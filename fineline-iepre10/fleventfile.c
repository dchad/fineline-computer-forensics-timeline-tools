
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
   fleventfile.c

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 22/12/2013

   Purpose: fineline event file creation and writing.

*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "fineline-iepre10.h"

/*
   Function: open_event_file()

   Purpose : Creates the event record event file in the current working directory.
   Input   : event filename.
   Output  : Returns event file pointer.
*/
FILE *open_fineline_event_file(char *evt_file_name)
{
    FILE *event_file;
    event_file = fopen(evt_file_name, "a");
    if (event_file == NULL)
    {
       printf("open_fineline_event_file() <ERROR>: could not open event file: %s\n", evt_file_name);
    }
    printf("open_event_file() <INFO> open_fineline_event_file(): %s\n", evt_file_name);

   return(event_file);
}


/* DEPRECATED: format superseded.
   Function: write_fineline_event_record()

   Purpose : Creates an event string and prints to the fineline event file and stdout.
           :
   Input   : Event string, event file and log file.
   Output  : Timestamped event entry.
*/
int write_fineline_event_record(char *estr, FILE *evt_file)
{
   time_t curtime;
   struct tm *loctime;
   int slen = strlen(estr) + 100;
   char *event = (char *)xcalloc(slen);
   char *time_str;

   /* Get the current time. */
   curtime = time (NULL);
   loctime = localtime (&curtime);

   time_str = asctime(loctime);
   strncpy(event, time_str, strlen(time_str) - 1);
   strncat(event, " ", 1);
   strncat(event, estr, slen);

   fputs (event, evt_file);

   printf("%s", event);

   xfree(event, slen);

   return(0);
}

/*
   Function: write_fineline_project_header()

   Purpose : Creates a project file header string and prints to the project file.
           :
   Input   : Fineline project header string, event file and record count.
   Output  : Timestamped project header entry.
*/
int write_fineline_project_header(char *pstr, FILE *evt_file, int record_count)
{
   time_t curtime;
   struct tm *loctime;
   int slen = strlen(pstr) + FL_MAX_INPUT_STR;
   char *hdr = (char *) xcalloc(slen);
   char *time_str;
   char start_date_time_string[32];
   char end_date_time_string[32];
   /* struct fl_event_record *fler; */

   memset(start_date_time_string, 0, 32);
   memset(end_date_time_string, 0, 32);

   strncpy(start_date_time_string, "NONE", 4);
   strncpy(end_date_time_string, "NONE", 4);

   /* Get the current time. */
   curtime = time (NULL);
   loctime = localtime (&curtime);
   time_str = asctime(loctime);

   /* Get the date of the first and last event records and use these to set the project start/end dates
   fler = get_first_event_record();
   if (fler != NULL)
   {
      strncpy(start_date_time_string, fler->event_time_string, 32);
   }
   fler = get_last_event_record();
   if (fler != NULL)
   {
      strncpy(end_date_time_string, fler->event_time_string, 32);
   }
   */

   /* First and last records are same day because event file is a circular buffer with a fixed maximum size */
   /* TODO: determine a method of getting the last date/time stamp from the event file */

   strcpy(hdr, "<project><name>FineLine Project ");
   strncat(hdr, time_str, strlen(time_str) - 1);
   strcat(hdr, "</name><investigator>NONE</investigator><summary>NONE</summary><startdate>");
   strncat(hdr, start_date_time_string, 32);
   strcat(hdr,"</startdate><enddate>");
   strncat(hdr, end_date_time_string, 32);
   strcat(hdr, "</enddate><description>");
   strncat(hdr, pstr, slen);
   strcat(hdr, "</description></project>\n");
   fputs (hdr, evt_file);

   print_log_entry("write_fineline_project_header() <INFO> Wrote Project Header.\n");

   xfree(hdr, slen);

   return(0);
}



