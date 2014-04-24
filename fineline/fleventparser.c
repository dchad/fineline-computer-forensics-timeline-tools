

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
   fleventparser.c

   Title : FineLine Computer Forensics Timeline Constructor Utilities
   Author: Derek Chadwick
   Date  : 22/12/2013

   Purpose: Wrapper functions for various standard C lib functions to
            make them safer.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fineline.h"

int parse_evtx_event_log(char *evtx_file, char *fl_event_file, int mode, char *gui_ip_addr, char *filter_filename)
{
   libevtx_file_t *evtxf = NULL;
   
   if (load_windows_event_id_hashmap() < 0)
   {
      print_log_entry("parse_evtx_event_log() <ERROR> Could not load event list hashmap.\n");
      return(-1);
   }

   if (mode & FL_FILTER_ON)
   {
      if (load_event_filters(filter_filename) < 0)
      {
         print_log_entry("parse_evtx_event_log() <ERROR> Could not load filter list file.\n");
         return(-1);
      }
   }

   if (evtx_file_initialise(&evtxf) < 0)
   {
      print_log_entry("parse_evtx_event_log() <ERROR> Could not initialise libevtx file.\n");
      return(-1);
   }

   if (evtx_file_open(evtxf, evtx_file) < 0)
   {
      print_log_entry("parse_evtx_event_log() <ERROR> Could not open libevtx file.\n");
      return(-1);
   }
  
   if (evtx_process_file(evtxf, fl_event_file, mode, gui_ip_addr) < 0)
   {
      print_log_entry("parse_evtx_event_log() <ERROR> Could not process libevtx file.\n");
      return(-1);
   }
   
   if (evtx_file_close(evtxf) < 0)
   {
      print_log_entry("parse_evtx_event_log() <ERROR> Could not close libevtx file.\n");
      return(-1);
   }
   
   if (evtx_file_free(&evtxf) < 0)
   {
      print_log_entry("parse_evtx_event_log() <ERROR> Could not free libevtx file.\n");
      return(-1);
   }
   return(0);
}


int parse_evt_event_log(char *evt_file, char *fl_event_file, int mode, char *gui_ip_addr, char *filter_filename)
{
   libevt_file_t *evtf = NULL;
   
   if (load_windows_event_id_hashmap() < 0)
   {
      print_log_entry("parse_evt_event_log() <ERROR> Could not load event list hashmap.\n");
      return(-1);
   }

   if (mode & FL_FILTER_ON)
   {
      if (load_event_filters(filter_filename) < 0)
      {
         print_log_entry("parse_evt_event_log() <ERROR> Could not load filter list file.\n");
         return(-1);
      }
   }

   if (evt_file_initialise(&evtf) < 0)
   {
      print_log_entry("parse_evt_event_log() <ERROR> Could not initialise libevt file.\n");
      return(-1);
   }

   if (evt_file_open(evtf, evt_file) < 0)
   {
      print_log_entry("parse_evt_event_log() <ERROR> Could not open libevt file.\n");
      return(-1);
   }
  
   if (evt_process_file(evtf, fl_event_file, mode, gui_ip_addr) < 0)
   {
      print_log_entry("parse_evt_event_log() <ERROR> Could not process libevt file.\n");
      return(-1);
   }
   
   if (evt_file_close(evtf) < 0)
   {
      print_log_entry("parse_evt_event_log() <ERROR> Could not close libevt file.\n");
      return(-1);
   }
   
   if (evt_file_free(&evtf) < 0)
   {
      print_log_entry("parse_evt_event_log() <ERROR> Could not free libevt file.\n");
      return(-1);
   }

   return(0);

}



int parse_event_log(FILE *db_file, char *gui_ip_addr)
{
   FILE *system_log;
   FILE *security_log;
   FILE *application_log;
   /*
   FILE *event_db_file;
   EVENTLOGEOF evt_log_eof;
   EVENTLOGHEADER evt_log_hdr;
   EVENTLOGRECORD evt_log_rec;
   char evt_str[1024];
   */

  /* open the event database file for writing windows events */
   if (db_file == NULL)
   {
      print_log_entry("parse_event_logs() <ERROR> Invalid database file handle.\n");
      return(-1);
   }

  /* open system event log D:\project\fineline\System.evtx */
   if ((system_log = fopen("D:\\project\\fineline\\System.evtx", "rb")) != NULL)
   {
      /* read_event_log_header(system_log, db_file);
      extract_system_event_records(system_log); */
   }
   else
   {
      print_log_entry("parse_event_logs() <ERROR> Could not open System.evtx.\n");
   }

  /* open security event log */
   if ((security_log = fopen("D:\\project\\fineline\\Security.evtx", "rb")) != NULL)
   {
      /* extract_security_event_records(security_log); */
   }
   else
   {
      print_log_entry("parse_event_logs() <ERROR> Could not open Security.evtx.\n");
   }

  /* open application event log */
   if ((application_log = fopen("D:\\project\\fineline\\Application.evtx", "rb")) != NULL)
   {
      /* extract_application_event_records(application_log); */
   }
   else
   {
      print_log_entry("parse_event_logs() <ERROR> Could not open Application.evtx.\n");
   }

   fclose(system_log);
   fclose(security_log);
   fclose(application_log);

   return(0);
}

int extract_system_event_records(FILE *sys_log)
{


   return(0);
}

int extract_security_event_records(FILE *sec_log)
{

   return(0);
}

int extract_application_event_records(FILE *app_log)
{

   return(0);
}

/*
   Function: event_to_string()

   Purpose : Converts a Windows event record to a single comma delimited string.
           :
   Input   : Windows EVENTLOGRECORD.
   Output  : Event string.
*/
int event_to_string(char *evt_str)
{
   if (strlen(evt_str) > 0)
   {

   }

   return(0);
}


/*
   Function: read_evtx_header()

   Purpose : Read Windows evtx event log header and converts to a single comma delimited string.
           :
   Input   : evtx file, database file, log file.
   Output  : Event string.
*/
int read_evtx_header(FILE *evt_file, FILE *db_file)
{
   /* unsigned long hdr_rec[12];
    char temp_buf[48]; */
   char evt_str[1024];

   strncpy (evt_str, "HEADER: ", 8);
   return(0);
}


/*
   Function: read_evt_header()

   Purpose : Read event log header and converts to a single comma delimited string.
           :
   Input   : Windows EVENTLOGHEADER.
   Output  : Event string.
*/
int read_evt_header(FILE *evt_file, FILE *db_file)
{
   /* unsigned long hdr_rec[12];
    char temp_buf[48]; */
   char evt_str[1024];

   strncpy (evt_str, "HEADER: ", 8);
   return(0);
}


/*
   Function: read_event_log_header() ****DEPRECATED****

   Purpose : Read event log header and converts to a single comma delimited string.
           :
   Input   : Windows EVENTLOGHEADER.
   Output  : Event string.
*/
int read_event_log_header(FILE *evt_file, FILE *db_file)
{
   /* unsigned long hdr_rec[12];
    char temp_buf[48]; */
   char evt_str[1024];
   char temp_str[100];

   strncpy (evt_str, "HEADER: ", 8);
   /* int numread = fread(temp_buf, 4, 12, evt_file); unsigned long = 32 bits */
   /* int numread = fread(hdr_rec, 4, 12, evt_file); */
   if (fgets(temp_str, 100, evt_file) == NULL)
   {
      print_log_entry("read_event_log_header() <ERROR> Invalid read of event log header record.\n");
   }
   else
   {




      /* strncat(evt_str, temp_str, 100);
      memcpy(hdr_rec, temp_buf, 48);
      char hex_val[10];
      int i;
      for(i = 0; i < 48; i++)
      {
         sprintf(hex_val, "%x", temp_str[i]);
         printf("%s:", hex_val);
         strncat(evt_str, hex_val, 8);
         strncat(evt_str, ", ", 2);
      }
      */

      printf("\nDEBUG>%s", evt_str);
   }
   return(0);
}
