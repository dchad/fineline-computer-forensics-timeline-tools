

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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fineline.h"

#include "libfdatetime_date_time_values.h"
#include "libfdatetime_definitions.h"
#include "libfdatetime_fat_date_time.h"
#include "libfdatetime_filetime.h"
#include "libfdatetime_floatingtime.h"
#include "libfdatetime_nsf_timedate.h"
#include "libfdatetime_posix_time.h"
#include "libfdatetime_systemtime.h"
#include "libfdatetime_types.h"




int evt_file_initialise(libevt_file_t **evtf)
{
   libevt_error_t *error = NULL;
   int err = 0;
   if ((err = libevt_file_initialize(evtf, &error)) != 1)
   {
      print_log_entry("evt_file_initialise() <ERROR> Could not initialise libevt file.\n");
      return(-1);
   }
   
    return(0);
}

int evt_file_open(libevt_file_t *evtf, char* filename)
{
   libevt_error_t *error = NULL;
   if(libevt_file_open(evtf, filename, LIBEVT_OPEN_READ, &error ) != 1)
   {
      print_log_entry("evt_file_open() <ERROR> Could not open evt event file.\n");
      return(-1);
   }

   return(0);
}

int evt_process_file(libevt_file_t *evtf, char *fl_event_filename, int mode, char *gui_addr)
{
   libevt_error_t *error = NULL;
   libevt_record_t *record = NULL;
   char current_id[32];
   char current_time[32];
   char prev_id[32];
   char prev_time[32];
   int number_of_records   = 0;
   char record_count_string[256];
   int i, result, filtered_count = 0, non_filtered_count = 0;
   FILE *fl_evt_file = NULL;
   uint64_t first_record_number;
   struct fl_event_record * fler;

   /*
      1. Open/create the fineline project file or GUI socket or both.
      2. Generate a project header.
      3. Get the number of event records in the evt file.
      4. Write the project header to the fineline project file or GUI socket or both.
      5. Read each event from the evt event file.
      6. Parse the evt event record and generate a fineline event record.
      7. Write the fineline event record to the project file or GUI socket or both.
      8. When no more evt events, close files and exit.
   */

   memset(current_id, 0, 32);   /* !!!CLEAR THE BUFFERS!!! */
   memset(current_time, 0, 32);
   memset(prev_id, 0, 32);
   memset(prev_time, 0, 32);

   if (libevt_file_get_number_of_records(evtf, &number_of_records, &error) != 1)
	{
      print_log_entry("evt_process_file() <ERROR> Could not get evt record count.\n");
	   return(-1);
	}
   
	if (number_of_records == 0)
	{
	   printf("evt_process_file() <INFO> No records found.\n");
	   return(0);
	}

   /* if -d mode then open the fineline event file for output */
   if (mode & FL_FILE_OUT)
   {
      fl_evt_file = open_fineline_event_file(fl_event_filename);

      if (fl_evt_file == NULL)
      {
         print_log_entry("evt_process_file() <ERROR> Failed to open FineLine event file.\n");
         return(-1);
      }
   }
	/* create the socket to the GUI */
	if (mode & FL_GUI_OUT)
	{
		result = init_socket(gui_addr);
		if (result < 0)
		{
		   print_log_entry("evt_process_file() <ERROR> Could not open socket to GUI.\n");
			return(-1);
		}
	}

   sprintf(record_count_string, "evt_process_file() <INFO> Processing %d event records\n", number_of_records);
   print_log_entry(record_count_string);

	for (i = 0; i < number_of_records; i++)
	{

		if( libevt_file_get_record(evtf, i, &record, &error ) != 1 )
		{
			print_log_entry("evt_process_file() <ERROR> Could not get evt record.\n");
			return(-1);
		}
      fler = (struct fl_event_record *)xcalloc(sizeof(struct fl_event_record));
      result = evt_parse_event_record(record, fler, mode, current_id, current_time);

      /* if result is less than zero then an error occurred processing the event record.
         if result is equal to zero then process the event.
         if the result is greater than zero then this event type is being filtered out.
      */
		if (result < 0)
		{
          print_log_entry("evt_process_file() <ERROR> Could not parse evt record.\n");
          return(-1);
		} 
      else if (result == 0) /* filter for this event type was not set in the filter file */
      {
         if (filter_duplicate_events(current_id, current_time, prev_id, prev_time) == 0)
         {
            add_event_record(fler->id, fler);
            non_filtered_count++;
         }
         else
         {
            filtered_count++;
            xfree((char *)fler, sizeof(struct fl_event_record));
         }
      }
      else
      {
         filtered_count++;
         xfree((char *)fler, sizeof(struct fl_event_record));
      }

      if( libevt_record_free(&record, &error) != 1 )
      {
         print_log_entry("evt_process_file() <ERROR> Could not free evt record.\n");
      }
      record = NULL; /* have to reset to null or libevt generates an error */
      error = NULL;

      if ((i % 100) == 0)
      {
         sprintf(record_count_string, "evt_process_file() <INFO> Processed %d event records\n", i);
         print_log_entry(record_count_string);
      }

   }

   /* sprintf(record_count_string, "evt_process_file() <INFO> Sorting %d event records\n", non_filtered_count);
   print_log_entry(record_count_string); */

   /* now sort the event records into time order */
   first_record_number = get_first_record_number();

   /* write the event to file */
   if (mode & FL_FILE_OUT)
   {
      write_fineline_project_header("NEW PROJECT", fl_evt_file, number_of_records);

      sprintf(record_count_string, "evt_process_file() <INFO> Writing %d event records\n", number_of_records);
      print_log_entry(record_count_string);

      write_event_map_in_time_sequence(fl_evt_file, first_record_number);
      /* printf("evt_process_file() <INFO> Event Record: %s\n", event_string); */
   }
   /* send the event to the gui */
   if (mode & FL_GUI_OUT)
   {
      sprintf(record_count_string, "evt_process_file() <INFO> Sending %d event records\n", number_of_records);
      print_log_entry(record_count_string);

      send_event_map_in_time_sequence(first_record_number);
   }

   sprintf(record_count_string, "evt_process_file() <INFO> Processed %d event records <Filtered = %d, Non-Filtered = %d\n", i, filtered_count, non_filtered_count);
   print_log_entry(record_count_string);

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

   return(0);
}


int evt_file_close(libevt_file_t *evtf)
{
   libevt_error_t *error;

   if(libevt_file_close(evtf, &error) != 0)
   {
      print_log_entry("evt_file_close() <ERROR> Could not close evt event file.\n");
      return(-1);
   }

	return(0);
}


int evt_file_free(libevt_file_t **evtf)
{
   libevt_error_t *error;
   if( libevt_file_free(evtf, &error) != 1 )
   {
      print_log_entry("evt_file_free() <ERROR> Could not free evt event file.\n");
      return(-1);
   }
   return(0);
}

int evt_parse_event_record(libevt_record_t *record, struct fl_event_record *fler, int mode, char *current_id, char *current_time)
{
   libevt_error_t *error                   = NULL;
   char *source_name                       = NULL;
   char *value_string                      = NULL;
   size_t source_name_size                 = 0;
   size_t value_string_size                = 0;
   uint64_t time_val                       = 0;
   uint32_t event_number                   = 0;
   uint32_t event_identifier               = 0;
   uint8_t event_level                     = 0;
   int result                              = 0;
   int total_string_size                   = 0;
   char date_time_string[ 32 ];
   struct fl_windows_event_id *fled = NULL;
   char event_data[FL_MAX_INPUT_STR];
   char message_string[FL_MAX_INPUT_STR];
   char *event_string;

   memset(event_data, 0, FL_MAX_INPUT_STR);
   memset(date_time_string, 0, 32);

   /* get windows event id number */
   if( libevt_record_get_event_identifier(record, &event_identifier, &error ) != 1 )
   {
      print_log_entry("evt_parse_event_record() <ERROR> Could not get event identifier.\n");
	   event_identifier = 0;
   }

   /* check if this event type is being filtered out, if not then continue processing the record */
   if ((fled = find_windows_event_id(event_identifier)))
   {
      if (mode & FL_FILTER_ON)
      {
         if (fled->filter_out == 1)
         {
            return(1);
         }
      }
   }
   
   /* get the event time */
   if (evt_get_date_time_string(record, &time_val, date_time_string) < 0)
   {
      print_log_entry("evt_parse_event_record() <ERROR> Could not get event time string.\n");
	   return(-1);
   }
   
   /* get the record number, this is the sequence number of the record in the event log, not the event type identifier */
   if(libevt_record_get_identifier(record, &event_number, &error) != 1 )
   {
      print_log_entry("evt_parse_event_record() <ERROR> Could not get event record identifier.\n");
      event_number = 0;
   }

   value_string = (char *)xcalloc(20);
   strcpy(event_data, xitoa((int)event_number, value_string, 20, 10));
   strncat(event_data, " | ", 3);
   total_string_size += strlen(value_string) + 3;
   xfree(value_string, 20);
   
   /* get the event level (VERBOSE=5, INFO=0 or 4, WARNING=3, ERROR=2, CRITICAL=1) ??? */
   event_level = 0;

   /* get user security identifier */
   result = libevt_record_get_utf8_user_security_identifier_size(record, &value_string_size, &error );
   if (result == -1)
   {
      print_log_entry("evt_parse_event_record() <ERROR> Could not get security identifier size.\n");
   }
   else if (result > 0)
   {
      value_string = (char *)xcalloc(value_string_size);
      result = libevt_record_get_utf8_user_security_identifier(record, (uint8_t *) value_string, value_string_size, &error);
      if (result == -1)
      {
         print_log_entry("evt_parse_event_record() <ERROR> Could not get use security identifier string.\n");
      }
      else
      {
        strncat(event_data, value_string, value_string_size);
        strncat(event_data, " | ", 3);
        total_string_size += value_string_size + 3;
      }
      xfree(value_string, value_string_size);
      value_string = NULL;
   }
   
   /* get computer name */
   result = libevt_record_get_utf8_computer_name_size(record, &value_string_size, &error);
   if (result == -1)
   {
      print_log_entry("evt_parse_event_record() <ERROR> Could not get computer name size.\n");
   }
   else if (result > 0)
   {
      value_string = (char *)xcalloc(value_string_size);
      result = libevt_record_get_utf8_computer_name(record, (uint8_t *) value_string, value_string_size, &error);
      if (result == -1)
      {
         print_log_entry("evt_parse_event_record() <ERROR> Could not get computer name string.\n");
      }
      else
      {
         strncat(event_data, value_string, value_string_size);
         strncat(event_data, " | ", 3);
         total_string_size += value_string_size + 3;
      }
      xfree(value_string, value_string_size);
      value_string = NULL;
   }

   /* get name of source or event */
   result = libevt_record_get_utf8_source_name_size(record, &source_name_size, &error);
   if (result == -1)
   {
      print_log_entry("evt_parse_event_record() <ERROR> Could not get event source name size.\n");
   }
   else if (result > 0)
   {
      source_name = (char *) xcalloc(source_name_size);
      result = libevt_record_get_utf8_source_name(record, (uint8_t *) source_name, source_name_size, &error);
      if (result == -1)
      {
         print_log_entry("evt_parse_event_record() <ERROR> Could not get source name string.\n");
      }
      else
      {
         strncat(event_data, source_name, source_name_size);
         total_string_size += source_name_size;
      }
      xfree(source_name, source_name_size);
   }

   result = evt_get_message_strings(record, message_string);
   if (result > 0)
   {
      if ((total_string_size + result) < FL_MAX_INPUT_STR)
      {
         strncat(event_data, message_string, strlen(message_string));
         total_string_size += result;
      }
      else
      {
         print_log_entry("evt_parse_event_record() <INFO> Excluding message strings - too long.\n");
      }
   }
   /* else
   {
      print_log_entry("evt_parse_event_record() <INFO> No message strings found in record.\n");
   } */


   event_string = (char *)xcalloc(FL_MAX_INPUT_STR);

   strcpy(event_string, "<event><id>");
   xitoa(event_identifier, current_id, 30, 10); /* this is the Windows event identifier, not the event record number */
   strcat(event_string, current_id);
   strcat(event_string, "</id><evidencenumber>NONE</evidencenumber><time>");
   strncpy(current_time, date_time_string, 30);
   strcat(event_string, date_time_string);
   strcat(event_string, "</time><type>");
   strcat(event_string, get_event_level_text(event_level));
   strcat(event_string, "</type><summary>"); 
   
   /* now lookup windows event id description and put it in the event summary field */
   if (fled != NULL)
   {
      strcat(event_string, fled->event_description);
   }
   else
   { 
      strcat(event_string, "UNIDENTIFIED EVENT");
   }
   strcat(event_string, "</summary><data>");
   strcat(event_string, event_data); 
   strcat(event_string, "</data><hiddenevent>0</hiddenevent><hiddentext>0</hiddentext><marked>0</marked><pinned>0</pinned><ypos>0</ypos></event>\n");

   /* now add the fineline event record to the hashmap, the event time will later be used to sort the event records into time sequence */
   fler->id = event_number;
   fler->event_time = (double)time_val;
   strncpy(fler->event_time_string, date_time_string, 32);
   strncpy(fler->event_record_string, event_string, FL_MAX_INPUT_STR);

   xfree(event_string, FL_MAX_INPUT_STR);

   /* printf("evt_parse_event_record() <INFO> Parsed event: %d\n", event_number); */
   
   return(0);
}



int evt_get_date_time_string(libevt_record_t *record, uint64_t *time_val, char *date_time_string)
{
   libevt_error_t *error = NULL;
   libfdatetime_filetime_t *filetime = NULL;
   libfdatetime_date_time_values_t *date_time_values = NULL;
   uint32_t value_32bit = 0;

  /* get the event time */
   if(libfdatetime_filetime_initialize(&filetime, &error) != 1 )
   {
      print_log_entry("get_date_time_string() <ERROR> Could not initialise file time.\n");
      return(-1);
   }
   	
   if (libfdatetime_date_time_values_initialize(&date_time_values, &error) != 1)
   {
      print_log_entry("get_date_time_string() <ERROR> Could not initialise date time values.\n");
      return(-1);
   }

   if(libevt_record_get_written_time(record, &value_32bit, &error) != 1)
   {
      print_log_entry("get_date_time_string() <ERROR> Could not get event time.\n");
      return(-1);
   }

   *time_val = value_32bit;
   if(libfdatetime_filetime_copy_from_64bit(filetime, *time_val, &error) != 1)
   {
      print_log_entry("get_date_time_string() <ERROR> Could not copy file time.\n");
      return(-1);
   }

   if (libfdatetime_filetime_copy_to_date_time_values((libfdatetime_internal_filetime_t *)filetime, date_time_values, &error ) != 1)
   {
      print_log_entry("get_date_time_string() <ERROR> Could not get event date and time values.\n");
      return(-1);
   }

   /* FineLine date/time format is DD/MM/YYYY HH:MM:SS */
   sprintf(date_time_string, "%02d/%02d/%04d %02d:%02d:%02d", date_time_values->day, date_time_values->month, date_time_values->year, date_time_values->hours, date_time_values->minutes, date_time_values->seconds);

   if(libfdatetime_filetime_free(&filetime, &error) != 1)
   {
      print_log_entry("get_date_time_string() <ERROR> Could not free filetime.\n");
   }
   
   if(libfdatetime_date_time_values_free(&date_time_values, &error) != 1)
   {
      print_log_entry("get_date_time_string() <ERROR> Could not free date time values.\n");
   }

   return(0);
}

int evt_get_message_strings(libevt_record_t *record, char *mess_string)
{
   int number_of_strings = 0;
   int i, total_length = 0;
   size_t value_string_size = 0;
   libevt_error_t *error = NULL;
   char *value_string;
   char index_string[32];
   
   memset(mess_string, 0, FL_MAX_INPUT_STR);

   if(libevt_record_get_number_of_strings(record, &number_of_strings, &error) != 1 )
   {
      print_log_entry("get_message_strings() <ERROR> Could not get number of message strings.\n");
      return(0);
   }
   for(i = 0; i < number_of_strings; i++)
   {
      if (libevt_record_get_utf8_string_size(record, i, &value_string_size, &error) != 1 )
      {
         print_log_entry("get_message_strings() <ERROR> Could not get message string size.\n");
         return(0);
      }
      if( value_string_size > 0 )
      {
         value_string = (char *)xcalloc(value_string_size);
         if (libevt_record_get_utf8_string( record, i, (uint8_t *) value_string, value_string_size, &error) != 1)
         {
            print_log_entry("get_message_strings() <ERROR> Could not get message string.\n");
            return(0);
         }
         if ((total_length + value_string_size) < FL_MAX_INPUT_STR)
         {
            memset(index_string, 0, 32);
            xitoa(i, index_string, 32, 10);
            strncat(mess_string, "<mstring", 8);
            strncat(mess_string, index_string, strlen(index_string));
            strncat(mess_string, ">", 1);
            strncat(mess_string, value_string, value_string_size);
            strncat(mess_string, "</mstring", 9);
            strncat(mess_string, index_string, strlen(index_string));
            strncat(mess_string, ">", 1);
            total_length += value_string_size;
            xfree(value_string, value_string_size);
         }
         else
         {
            xfree(value_string, value_string_size);
            break;
         }
      }
   }
   return(total_length);
}
