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
   flieindexparser.c

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 02/03/2014

   Purpose: Analyses Internet Explorer 1 - 9 index.dat cache files
            and outputs the urls in FineLine Event format.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fineline-iepre10.h"
#include <libfdatetime_date_time_values.h>
#include <libfdatetime_definitions.h>
#include <libfdatetime_error.h>
#include <libfdatetime_fat_date_time.h>
#include <libfdatetime_filetime.h>
#include <libfdatetime_nsf_timedate.h>
#include <libfdatetime_posix_time.h>
#include <libfdatetime_types.h>

int parse_ie_index_file(char *iecfile, char *fl_event_filename, int mode, char *gui_ip_addr, char *filter_filename)
{
   libcerror_error_t *error     = NULL;
   libmsiecf_file_t *input_file = NULL;
   libmsiecf_item_t *url_item   = NULL;
   int item_iterator      = 0;
   int number_of_items    = 0;
   FILE *fl_evt_file = NULL;

   if(libmsiecf_file_initialize(&input_file, &error) != 1)
   {
      print_log_entry("parse_ie_cache_file() <ERROR> Could not initialise input file.\n");
      return(-1);
   }

   if(libmsiecf_file_open(input_file, iecfile, LIBMSIECF_OPEN_READ, &error) != 1)
   {
      print_log_entry("parse_ie_cache_file() <ERROR> Could not open input file.\n");      
      return(-1);
   }

   /* Now parse the cache file */

   if(libmsiecf_file_get_number_of_items(input_file, &number_of_items, &error) != 1)
   {
      print_log_entry("parse_ie_cache_file() <ERROR> Could not get number of items.\n");
      return(-1);
   }
   printf("parse_ie_cache_file() <INFO> Number of items: %d.\n", number_of_items );

   /* if -w mode then open the fineline event file for output */
   if (mode & FL_FILE_OUT)
   {
      fl_evt_file = open_fineline_event_file(fl_event_filename);

      if (fl_evt_file == NULL)
      {
         print_log_entry("parse_ie_cache_file() <ERROR> Failed to open FineLine event file.\n");
         return(-1);
      }
   }
   /* if -s mode then create the socket to the GUI */
   if (mode & FL_GUI_OUT)
   {
      if (init_socket(gui_ip_addr))
      {
         print_log_entry("parse_ie_cache_file() <ERROR> Could not open socket to GUI.\n");
         return(-1);
      }
   }
   /* if -f mode then open the filter file */
   if (mode & FL_FILTER_ON)
   {
      if (load_url_filters(filter_filename) < 0)
      {
         print_log_entry("parse_ie_cache_file() <ERROR> Could not load URL filter file.\n");
         return(-1);
      }
   }

   /* Now iterate over the url items */
   for( item_iterator = 0; item_iterator < number_of_items; item_iterator++ )
   {
      if(libmsiecf_file_get_item(input_file, item_iterator, &url_item, &error) != 1)
      {
         print_log_entry("parse_ie_cache_file() <ERROR> Could not get URL item.\n");
         return(-1);
      }

      if(process_url_item(url_item, item_iterator, mode) < 0)
      {
         print_log_entry("parse_ie_cache_file() <ERROR> Could not process URL item.\n");
      }

      if(libmsiecf_item_free(&url_item, &error) != 1)
      {
         print_log_entry("parse_ie_cache_file() <ERROR> Could not free URL item.\n");
         return( -1 );
      }
	
   }

   if(libmsiecf_file_close(input_file, &error) != 0 )
   {
      print_log_entry("parse_ie_cache_file() <ERROR> Could not close input file.\n");      
      return(-1);
   }

   if(libmsiecf_file_free(&input_file, &error) != 1)
   {
      print_log_entry("parse_ie_cache_file() <ERROR> Could not free input file.\n");
      return(-1);      
   }
   
   /* Now sort the URL hashmap into time sequence order and output the URL events,
      can sort by primary time or by last checked time.                            */

   sort_by_primary_time();

   if (mode & FL_FILE_OUT)
   {
      write_url_map(fl_evt_file);
   }
  
   if (mode & FL_GUI_OUT)
   {
      send_url_map();
   }

   /* close the event output file */
   if (mode & FL_FILE_OUT)
   {
      fclose(fl_evt_file);
   }
   /* close the socket to the GUI */
   if (mode & FL_GUI_OUT)
   {
      close_socket();
   }

   printf("parse_ie_cache_file() <INFO> Processed %d URL items\n", number_of_items);

   return(0);
}

/*
   Function: process_url_item()

   Purpose : Gets the URL item type and extracts relevant data from the URL item.
   Input   : libmsiecf record pointer.
   Output  : Returns status value.

*/
int process_url_item(libmsiecf_item_t *url_item, int id, int mode)
{

   libcerror_error_t *error          = NULL;
   struct fl_url_record *url_record  = NULL;
   char *filename                    = NULL;
   char *location                    = NULL;
   libfdatetime_filetime_t *filetime = NULL;
   libfdatetime_fat_date_time_t *fat_date_time       = NULL;
   libfdatetime_date_time_values_t *date_time_values = NULL;
   char date_time_string[48];
   char dfat_time_string[48];
   size_t filename_size = 0;
   size_t location_size = 0;
   uint64_t value_64bit = 0;
   uint32_t value_32bit = 0;
   uint8_t item_type    = 0;

   /*
      Create a new FineLine URL event record, then extract the url string, last access time and access count
      from the cache URL record, then add the FineLine URL event record to the URL record hashmap for later
      sorting and output.
   */

   memset(date_time_string, 0, 48);
   memset(dfat_time_string, 0, 48);

   if(libmsiecf_item_get_type(url_item, &item_type, &error) != 1)
   {
      print_log_entry("process_url_item() <ERROR> Could not get url item type.\n");
      return(-1);
   }

   switch(item_type)
   {
      case LIBMSIECF_ITEM_TYPE_LEAK:
           return(0);

      case LIBMSIECF_ITEM_TYPE_REDIRECTED:
           return(0);

      case LIBMSIECF_ITEM_TYPE_URL:
           break;
      default:
           print_log_entry("process_url_item() <ERROR> Unknown item type.\n");
   }
   if(libfdatetime_fat_date_time_initialize(&fat_date_time, &error ) != 1)
   {
      print_log_entry("process_url_item() <ERROR> Could not initialise fat date time.\n");
      return(-1);
   }
   if(libfdatetime_filetime_initialize(&filetime, &error) != 1)
   {
      print_log_entry("process_url_item() <ERROR> Could not initialise filetime.\n");
      return(-1);
   }
   if (libfdatetime_date_time_values_initialize(&date_time_values, &error) != 1)
   {
      print_log_entry("process_url_item() <ERROR> Could not initialise date time values.\n");
      return(-1);
   }
   if(libmsiecf_url_get_utf8_location_size(url_item, &location_size, &error ) > 0)
   {
      if (location_size > 0)
      {
         location = xcalloc(location_size);
         if(libmsiecf_url_get_utf8_location(url_item, (uint8_t *) location, location_size, &error) != 1)
         {
            print_log_entry("process_url_item() <ERROR> Could not get location size.\n");
            return(-1);
         }
      }
   }

   /* Get the primary access time */
   if(libmsiecf_url_get_primary_time(url_item, &value_64bit, &error) != 1)
   {
      print_log_entry("process_url_item() <ERROR> Could not get primary filetime.\n");
      return(-1);
   }
   if(libfdatetime_filetime_copy_from_64bit(filetime, value_64bit, &error) != 1)
   {
      print_log_entry("process_url_item() <ERROR> Could not copy filetime.\n");
      return(-1);
   }
   if (libfdatetime_filetime_copy_to_date_time_values((libfdatetime_internal_filetime_t *)filetime, date_time_values, &error ) != 1)
   {
      print_log_entry("get_date_time_string() <ERROR> Could not get event date and time values.\n");
      return(-1);
   }

   /* FineLine date/time format is DD/MM/YYYY HH:MM:SS */
   sprintf(date_time_string, "%02d/%02d/%04d %02d:%02d:%02d", date_time_values->day, date_time_values->month, date_time_values->year, date_time_values->hours, date_time_values->minutes, date_time_values->seconds);

   /* Get the last access time */
   if(libmsiecf_url_get_last_checked_time(url_item, &value_32bit, &error) != 1)
   {
      print_log_entry("process_url_item() <ERROR> Could not get last access time.\n");
      return(-1);
   }
   if(libfdatetime_fat_date_time_copy_from_32bit(fat_date_time, value_32bit, &error) != 1)
   {
      print_log_entry("process_url_item() <ERROR> Could not copy fat time.\n");
      strncpy(dfat_time_string, "UNKNOWN", 7);
   }
   if(libfdatetime_fat_date_time_copy_to_utf8_string(fat_date_time,(uint8_t *) dfat_time_string, 48, LIBFDATETIME_STRING_FORMAT_TYPE_CTIME | LIBFDATETIME_STRING_FORMAT_FLAG_DATE_TIME, &error) != 1)
   {
      print_log_entry("process_url_item() <ERROR> Could not copy fat time to utf string.\n");
      return(-1);
   }

   /* Get the filename */
   if(libmsiecf_url_get_utf8_filename_size(url_item, &filename_size, &error ) > 0)
   {
      if(filename_size > 0)
      {
         filename = (char *)xcalloc(filename_size);
         if(libmsiecf_url_get_utf8_filename(url_item, (uint8_t *) filename, filename_size, &error) != 1)
         {
            print_log_entry("process_url_item() <ERROR> Could not get filename.\n");
            return(-1);
         }
      }
   }


   /* Now creat the fineline URL record and fill in the relevant values */
   url_record = (struct fl_url_record *) xcalloc(sizeof(struct fl_url_record));
   url_record->id = id;
   url_record->url_primary_time = (double)value_64bit;
   url_record->url_checked_time = (double)value_32bit;
   strncpy(url_record->url_primary_time_string, date_time_string, 48);
   strncpy(url_record->url_checked_time_string, dfat_time_string, 48);
   strncpy(url_record->url_location_string, location, 256);
   strncpy(url_record->url_filename_string, filename, 256);

   /* check URL filtering */
   if (mode & FL_FILTER_ON)
   {
      if (match_url_filter(url_record->url_location_string) > 0)
      {
         /* now add the URL record to the url hashmap */
         format_url_event_string(url_record);
         add_url_record(url_record->id, url_record);
      }
      else
      {
         xfree((char *)url_record, sizeof(struct fl_url_record));
      }
   }
   else
   {
      /* now add the URL record to the url hashmap */
      format_url_event_string(url_record);
      add_url_record(url_record->id, url_record);
   }


   /* We are done, clean up */
   if( libfdatetime_fat_date_time_free(&fat_date_time, &error) != 1)
   {
      print_log_entry("process_url_item() <ERROR> Could not free fat time.\n");
      return(-1);
   }
   if(libfdatetime_filetime_free(&filetime, &error) != 1)
   {
      print_log_entry("process_url_item() <ERROR> Could not free filetime.\n");
      return(-1);
   }

   xfree(location, location_size);
   xfree(filename, filename_size);

   /* print_log_entry("process_url_item() <INFO> Processed URL item.\n"); */

   return(0);
}

/*
   Function: format_url_event_string()

   Purpose : Creates a FineLine event record from the URL information.
   Input   : FineLine event record pointer.
   Output  : Returns status value.

*/
int format_url_event_string(struct fl_url_record *flurl)
{
   char event_string[FL_MAX_INPUT_STR];
   char event_data[FL_MAX_INPUT_STR];
   int  event_data_length = 0;
   int  total_str_length  = 0;

   memset(event_string, 0, FL_MAX_INPUT_STR);
   memset(event_data, 0, FL_MAX_INPUT_STR);

   /* 
      Now construct the URL record event data field.
   */

   strncpy(event_data, "<lastaccesstime>", 16);
   strncat(event_data, flurl->url_checked_time_string, 48);
   strncat(event_data, "</lastaccesstime><primarytime>", 30);
   strncat(event_data, flurl->url_primary_time_string, 48);
   strncat(event_data, "</primarytime><url>", 19);
   strncat(event_data, flurl->url_location_string, 256);
   strncat(event_data, "</url><filename>", 16);
   strncat(event_data, flurl->url_filename_string, 256);
   strncat(event_data, "</filename>", 11);
   event_data_length = strlen(event_data);

   total_str_length = event_data_length;

   /*
      Now construct the FineLine event record.
   */
   strncpy(event_string, "<event><id>", 11);
   strncat(event_string, "0000", 4);
   strncat(event_string, "</id><evidencenumber>NONE</evidencenumber><time>", 48);
   strncat(event_string, flurl->url_primary_time_string, 48);
   strncat(event_string, "</time><type>Internet Explorer 1-9</type><summary>", 50); 
   strncat(event_string, flurl->url_location_string, 256);
   strncat(event_string, "</summary><data>", 16);
   strncat(event_string, event_data, event_data_length); 
   strncat(event_string, "</data><hiddenevent>0</hiddenevent><hiddentext>0</hiddentext><marked>0</marked><pinned>0</pinned><ypos>0</ypos></event>\n", 120);
   total_str_length += 553;

   /* Maximum char count = */
   if (total_str_length < FL_MAX_INPUT_STR)
   {
      strncpy(flurl->url_record_string, event_string, strlen(event_string));
   }
   else
   {
      strncpy(flurl->url_record_string, event_string, FL_MAX_INPUT_STR);
   }
   
   return(0);
}








