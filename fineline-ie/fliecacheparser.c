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
   fliecacheparser.c

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 02/03/2014

   Purpose: Analyses Internet Explorer WebCacheV01.dat files
            and outputs the urls in FineLine Event format.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fineline-ie.h"

#include <libfdatetime_date_time_values.h>
#include <libfdatetime_definitions.h>
#include <libfdatetime_error.h>
#include <libfdatetime_fat_date_time.h>
#include <libfdatetime_filetime.h>
#include <libfdatetime_nsf_timedate.h>
#include <libfdatetime_posix_time.h>
#include <libfdatetime_types.h>

/*
   Function: process_ie_cache_file()

   Purpose : Opens the output file/socket then iterates over the tables in WebCacheV01.dat file and finds the Containers
             table. The Containers table is then searched to find the History and iedownload tables.
   Input   : libesed webcachev01.dat filename, output filename, mode, GUI IP address and filter filename.
   Output  : Returns status value.

*/

int parse_ie_cache_file(char *iecfile, char *fl_event_filename, int mode, char *gui_ip_addr, char *filter_filename)
{
   libcerror_error_t *error     = NULL;
   libesedb_file_t *input_file  = NULL;
   libesedb_table_t *table      = NULL;
   char *table_name;
   int table_index        = 0;
   int number_of_tables   = 0;
   size_t table_name_size    = 0;
   FILE *fl_evt_file = NULL;

   if(libesedb_file_initialize(&input_file, &error) != 1)
   {
      print_log_entry("parse_ie_cache_file() <ERROR> Could not initialise input file.\n");
      return(-1);
   }

   if(libesedb_file_open(input_file, iecfile, LIBESEDB_OPEN_READ, &error) != 1)
   {
      print_log_entry("parse_ie_cache_file() <ERROR> Could not open input file.\n");      
      return(-1);
   }

   /* Now get the number of tables in the cache file, we specifically want the 
      "History M" and "History L" tables. These record all the URLs and local files
      accessed by the user in roaming and locallow modes.
      Note: Roaming  = user data sent to an exchange server so it is available on
                       any computer in the logon domain.
            Local    = computer specific data that is only available on the local machine.
            LocalLow = browser restricted access folders (Low Priviledge).
   */
   if(libesedb_file_get_number_of_tables(input_file, &number_of_tables, &error ) != 1)
   {
      print_log_entry("parse_ie_cache_file() <ERROR> Could not get number of tables in cache file.\n");
      return(-1);
   }
   if( number_of_tables == 0 )
   {
      print_log_entry("parse_ie_cache_file() <INFO> No tables in cache file.\n");
      return( 0 );
   }

   printf("parse_ie_cache_file() <INFO> Number of tables: %d.\n", number_of_tables);

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
      /* TODO: send_fineline_project_header("NEW PROJECT", fl_evt_file); */
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

   for(table_index = 0; table_index < number_of_tables; table_index++)
   {
      if(libesedb_file_get_table(input_file, table_index, &table, &error) != 1 )
      {
         print_log_entry("parse_ie_cache_file() <ERROR> Could not get table.\n");
         return(-1);
      }
      if(libesedb_table_get_utf8_name_size(table, &table_name_size, &error) != 1)
      {
         print_log_entry("parse_ie_cache_file() <ERROR> Could not get table name size.\n");
         return(-1);
      }
      if(table_name_size > 0 )
      {
         table_name = (char *)xcalloc(table_name_size);
         if (libesedb_table_get_utf8_name(table, (uint8_t *) table_name, table_name_size, &error) != 1)
         {
            print_log_entry("parse_ie_cache_file() <ERROR> Could not get table name.\n");
            return(-1);
         }
      }
      /* printf("parse_ie_cache_file() <INFO> Found table: %s\n", table_name); */

      if (strncmp(table_name, "Containers", 10) == 0)
      {
         /*
           OK, we have found the Containers table, now parse it to found the records
           for the History M and History L tables, then we can lookup those tables
           by index number (Container_XX) and parse the URL/File histories in them.
         */
         if(process_containers_table(input_file, table, mode) < 0)
         {
            print_log_entry("parse_ie_cache_file() <ERROR> Could not process containers table.\n");
            return(-1);
         }
         else
         {
            sort_by_time();
            if (mode & FL_FILE_OUT)
            {
               write_url_map(fl_evt_file);
            }
  
            if (mode & FL_GUI_OUT)
            {
               send_url_map();
            }
         }
      }
      if(libesedb_table_free(&table, &error) != 1)
      {
         print_log_entry("parse_ie_cache_file() <ERROR> Could not free table.\n");
         return( -1 );
      }
      xfree(table_name, table_name_size);
   }

   if(libesedb_file_close(input_file, &error) != 0)
   {
      print_log_entry("parse_ie_cache_file() <ERROR> Could not close input file.\n");      
      return(-1);
   }

   if(libesedb_file_free(&input_file, &error) != 1)
   {
      print_log_entry("parse_ie_cache_file() <ERROR> Could not free input file.\n");
      return(-1);      
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
   return(0);
}

/*
   Function: process_containers_table()

   Purpose : Iterates of the Containers table and finds the history and download tables.
             This is required because container ids are different on every installation
             so if specific tables need to be accessed such as History M and History L
             then we must iterate over the Containers table and find the required container
             ids by checking the name value in each record.
   Input   : libesed webcachev01.dat file pointer and containers table pointer.
   Output  : Returns status value.

*/
int process_containers_table(libesedb_file_t *input_file, libesedb_table_t *table, int mode)
{
   libcerror_error_t *error   = NULL;
   libesedb_record_t *record  = NULL;
   int number_of_records  = 0;
   int number_of_values   = 0;
   int record_iterator    = 0;
   int value_iterator     = 0;
   size_t value_string_size  = 0;
   size_t value_data_size = 0;
   uint8_t value_flags    = 0;
   uint32_t column_type   = 0;
   int id_column          = 0;
   char *value_string;
   uint8_t *value_data = NULL;
  

   print_log_entry("process_containers_table() <INFO> Processing Containers Table.\n");


   id_column = get_container_id_column(table);
   if (id_column < 0)
   {
      print_log_entry("process_containers_table() <ERROR> Could not get container id column number.\n");
      return(-1);
   }

   if(libesedb_table_get_number_of_records(table, &number_of_records, &error) != 1)
   {
      print_log_entry("process_containers_table() <ERROR> Could not get number of records.\n");
      return(-1);
   }
   for(record_iterator = 0; record_iterator < number_of_records; record_iterator++)
   {
      if(libesedb_table_get_record(table, record_iterator, &record, &error) != 1)
      {
         print_log_entry("process_containers_table() <ERROR> Could not get record.\n");
         return(-1);
      }

      /* now iterate of the record values and print out */
      if(libesedb_record_get_number_of_values(record, &number_of_values, &error ) != 1)
      {
         print_log_entry("process_containers_table() <ERROR> Could not get number of values.\n");
         return( -1 );
      }
      for(value_iterator = 0; value_iterator < number_of_values; value_iterator++)
      {
         if(libesedb_record_get_column_type(record, value_iterator, &column_type, &error) != 1)
	 {
            print_log_entry("process_containers_table() <ERROR> Could not get column type.\n");            
            return( -1 );
	 }
         if(libesedb_record_get_value(record, value_iterator, &value_data, &value_data_size, &value_flags, &error) != 1)
         {
            print_log_entry("process_containers_table() <ERROR> Could not get record value.\n");
            return(-1);
         }
         if (column_type == LIBESEDB_COLUMN_TYPE_TEXT)
         {
            if (libesedb_record_get_value_utf8_string_size(record, value_iterator, &value_string_size, &error) != 1)
            {
               print_log_entry("process_containers_table() <ERROR> Could not get record value size.\n");
               return(-1);
            }
            value_string = (char *)xcalloc(value_string_size);
            if (libesedb_record_get_value_utf8_string(record, value_iterator, (uint8_t *)value_string, value_string_size, &error) != 1)
            {
               print_log_entry("process_containers_table() <ERROR> Could not get record value string.\n");
               return(-1);
            }
            /* printf("process_containers_table() <INFO> Found Table : %s\n", value_string); */

            if (strncmp(value_string, "History", 7) == 0)
            {
               if(process_history_table(input_file, record, id_column, mode) < 0)
               {
                  print_log_entry("process_containers_table() <ERROR> Could not process history table.\n");
                  return(-1);
               }
            }
            else if (strncmp(value_string, "iedownload", 7) == 0)
            {
               /* if(process_iedownload_table(input_file, record, id_column) < 0) DEPRECATED */
               if(process_history_table(input_file, record, id_column, mode) < 0)
               {
                  print_log_entry("process_containers_table() <ERROR> Could not process iedownload table.\n");
                  return(-1);
               }
            }
            xfree(value_string, value_string_size);
         }
      }
      if(libesedb_record_free(&record, &error) != 1)
      {
         print_log_entry("process_containers_table() <ERROR> Could not free record.\n");
         return( -1 );
      }
   }

   return(0);
}

/*
   Function: process_history_table()

   Purpose : Iterates over the records in the History table and outputs the URL, last access time and
             access count for each record.
   Input   : libesed webcachev01.dat file pointer, History table record for the Containers table.
   Output  : Returns status value.

*/

int process_history_table(libesedb_file_t *input_file, libesedb_record_t *container_record, int id_column, int mode)
{
   libcerror_error_t *error   = NULL;
   libesedb_record_t *record  = NULL;
   libesedb_table_t  *table   = NULL;
   int number_of_records     = 0;
   int number_of_values      = 0;
   int record_iterator       = 0;
   int value_iterator        = 0;
   size_t value_data_size    = 0;
   size_t utf8_string_size   = 0;
   uint8_t value_flags       = 0;
   uint32_t column_type      = 0;
   int filtered_records      = 0;
   char *utf8_string;
   uint8_t *value_data              = NULL;
   struct fl_url_record *url_record = NULL;
   int table_index;
   char last_access_time[32];

   print_log_entry("process_history_table() <INFO> Processing History Table.\n");

   /*
      Now get the container id for the history table then initialise the table and
      iterate over the records to extract the URLs, access count and last access time.
   */
   table_index = get_table_index(input_file, container_record, id_column);
   if (table_index < 0)
   {
      print_log_entry("parse_history_table() <ERROR> Could not get table index.\n");
      return(-1);
   }

   if(libesedb_file_get_table(input_file, table_index, &table, &error) != 1)
   {
      print_log_entry("parse_history_table() <ERROR> Could not get table.\n");
      return(-1);
   }

   if(libesedb_table_get_number_of_records(table, &number_of_records, &error) != 1)
   {
      print_log_entry("process_history_table() <ERROR> Could not get number of records.\n");
      return(-1);
   }

   printf("process_history_table() <INFO> Processing %d records.\n", number_of_records);

   for(record_iterator = 0; record_iterator < number_of_records; record_iterator++)
   {
      if(libesedb_table_get_record(table, record_iterator, &record, &error) != 1)
      {
         print_log_entry("process_history_table() <ERROR> Could not get record.\n");
         return(-1);
      }

      /* now iterate of the record values and print out */
      if(libesedb_record_get_number_of_values(record, &number_of_values, &error ) != 1)
      {
         print_log_entry("process_history_table() <ERROR> Could not get number of values.\n");
         return( -1 );
      }

      url_record = (struct fl_url_record *) xcalloc(sizeof(struct fl_url_record));

      for(value_iterator = 0; value_iterator < number_of_values; value_iterator++)
      {
         if(libesedb_record_get_column_type(record, value_iterator, &column_type, &error) != 1)
	 {
            print_log_entry("process_history_table() <ERROR> Could not get column type.\n");            
            return( -1 );
	 }
         if(libesedb_record_get_value(record, value_iterator, &value_data, &value_data_size, &value_flags, &error) != 1)
         {
            print_log_entry("process_history_table() <ERROR> Could not get record value.\n");
            return(-1);
         }
         if(libesedb_record_get_utf8_column_name_size(record, value_iterator, &utf8_string_size, &error ) < 0)
         {
            print_log_entry("process_history_table() <ERROR> Could not get column name size.\n");
            return(-1);
         }
         utf8_string = (char *)xcalloc(utf8_string_size);
         if(libesedb_record_get_utf8_column_name(record, value_iterator, (uint8_t *)utf8_string, utf8_string_size, &error) != 1)
         {
            print_log_entry("process_history_table() <ERROR> Could not get column name.\n");
            return(-1);
         }
         
         if (column_type == LIBESEDB_COLUMN_TYPE_DATE_TIME) /* get the last access time for the url */
         {                                                  /* this is not working, use 64bit column type instead */
            if(strncmp(utf8_string, "AccessedTime", 12) == 0)
            {
               /* get the date and time string and add to the URL record */
               if(get_date_time_string(record, value_iterator, url_record) < 0)
               {
                  print_log_entry("process_history_table() <ERROR> Could not get date time string.\n");
                  strncpy(last_access_time, "NONE", 4);
               }
               /* printf("process_history_table() <INFO> Access Time: %s\n", url_record->url_time_string); */
            }
            /* printf("process_history_table() <INFO> Got a date time column.\n"); */
         }
         else if ((column_type == LIBESEDB_COLUMN_TYPE_TEXT) || (column_type == LIBESEDB_COLUMN_TYPE_LARGE_TEXT))
         {
            if (strncmp(utf8_string, "Url", 3) == 0)
            {
               if (get_url_string(record, value_iterator, url_record) < 0)
               {
                  print_log_entry("process_history_table() <ERROR> Could not get URL string.\n");            
                  return( -1 );
               }
            }
         }
         else /* value is not a url or a date so check for the EntryId value */
         {
            if (strncmp(utf8_string, "EntryId", 7) == 0) /* we have the record identifier */
            {
               /* get the record id and use as the hashmap id because they are unique keys in the url table */

               /* TODO: CHECK IF GLOBALLY UNIQUE!!! */
               if (get_record_index(record, value_iterator, column_type, url_record) < 0)
               {
                  print_log_entry("process_history_table() <ERROR> Could not get record index.\n");            
                  return(-1);
               }
            }
            else if (strncmp(utf8_string, "AccessCount", 11) == 0)
            {
               /* get the URL access count and add to the URL record */
               if (get_access_count(record, value_iterator, column_type, url_record) < 0)
               {
                  print_log_entry("process_history_table() <ERROR> Could not get URL access count.\n"); 
                  /* not a fatal error */           
               }
            }
            else if(strncmp(utf8_string, "AccessedTime", 12) == 0)
            {
               /* get the date and time string and add to the URL record */
               if(get_date_time_string(record, value_iterator, url_record) < 0)
               {
                  print_log_entry("process_history_table() <ERROR> Could not get date time string.\n");
                  strncpy(last_access_time, "NONE", 4);
               }
               /* printf("process_history_table() <INFO> Access Time: %s\n", url_record->url_time_string); */
            }
         }

         xfree(utf8_string, utf8_string_size);
      }

      if(libesedb_record_free(&record, &error) != 1)
      {
         print_log_entry("process_history_table() <ERROR> Could not free record.\n");
         return(-1);
      }

      /* check URL filtering */
      if (mode & FL_FILTER_ON)
      {
         if (match_url_filter(url_record->url_record_string) > 0)
         {
            /* now add the URL record to the url hashmap */
            format_url_event_string(url_record);
            add_url_record(url_record->id, url_record);
         }
         else
         {
            filtered_records++;
         }
      }
      else
      {
         /* now add the URL record to the url hashmap */
         format_url_event_string(url_record);
         add_url_record(url_record->id, url_record);
      }

   }

   printf("process_history_table() <INFO> Processed %d records, filtered out %d records.\n", number_of_records, filtered_records);

   return(0);
}

/*
   Function: get_url_string()

   Purpose : Extracts the URL string from the url record and copies it to 
             the FineLine URL record.
   Input   : libesed webcachev01.dat table record from the History tables.
   Output  : Returns status value.

*/
int get_url_string(libesedb_record_t *record, int column, struct fl_url_record *flurl)
{
   libcerror_error_t *error   = NULL;
   char *value_string;
   size_t value_string_size  = 0;
   
   if (libesedb_record_get_value_utf8_string_size(record, column, &value_string_size, &error) < 0)
   {
      print_log_entry("get_url_string() <ERROR> Could not get record value size.\n");
      return(-1);
   }
   if (value_string_size > 10) /* get some crud entries if URL length is small */
   {
      value_string = (char *)xcalloc(value_string_size);
      if (libesedb_record_get_value_utf8_string(record, column, (uint8_t *)value_string, value_string_size, &error) != 1)
      {
         print_log_entry("get_url_string() <ERROR> Could not get record value string.\n");
         return(-1);
      }
      /* printf("process_history_table() <INFO> Found Url : %s\n", value_string); */
      /*
         Now copy the URL string to the FineLine URL record.
      */
      if (value_string_size < FL_MAX_INPUT_STR)
         strncpy(flurl->url_record_string, value_string, value_string_size);
      else
         strncpy(flurl->url_record_string, value_string, FL_MAX_INPUT_STR);

      xfree(value_string, value_string_size);
   } 
   else
   {
      strncpy(flurl->url_record_string, "INVALID URL", 11);
   }   

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
   char url_tld[256];
   char temp_str[32];
   char *question_mark    = NULL;
   char *user_name        = NULL;
   int  char_count        = 0;
   int  event_data_length = 0;
   int  url_string_length = 0;
   int  total_str_length  = 0;

   memset(event_string, 0, FL_MAX_INPUT_STR);
   memset(event_data, 0, FL_MAX_INPUT_STR);
   memset(url_tld, 0, 256);
   memset(temp_str, 0, 32);

   url_string_length = strlen(flurl->url_record_string);

   /*
      Now we need to get the URL domain name from the URL string to put into the summary field.
      The format of the URL string in WebCacheV01.dat History tables for local file access
      and remote web access:
      "Visited: user@file:///localfilepath/filename"
      "Visited: user@http://domain/path?query_string"
      So to get the username and domain we want to chop off the start and end of the string.
   */

   user_name = strchr(flurl->url_record_string, ' ');
   if (user_name != NULL)
   {

      question_mark = strrchr(flurl->url_record_string, '?');
      if (question_mark != NULL)
      {
         char_count = question_mark - user_name;
         if ((char_count > 0) && (char_count < 64))
         {
            strncpy(url_tld, user_name, char_count);
            total_str_length = char_count;
         }
         else
         {
            strncpy(url_tld, flurl->url_record_string, 32);
            total_str_length = 32;
         }
      }
      else
      {
         user_name++;
         strncpy(url_tld, user_name, strlen(user_name));
         total_str_length = strlen(user_name);
      }
   }
   else
   {
      strncpy(url_tld, flurl->url_record_string, 32);
      total_str_length = 32;
   }

   /* 
      Now construct the URL record event data field.
   */

   strncpy(event_data, "<lastaccesstime>", 16);
   strncat(event_data, flurl->url_time_string, 32);
   strncat(event_data, "</lastaccesstime><accesscount>", 30);
   strcat(event_data, xitoa((int)flurl->access_count, temp_str, 32, 10));
   strncat(event_data, "</accesscount><url>", 19);
   if (url_string_length < (FL_MAX_INPUT_STR - 512))
   {
      strncat(event_data, flurl->url_record_string, url_string_length);
   }
   else
   {
      strncat(event_data, flurl->url_record_string, (FL_MAX_INPUT_STR - 512));
   }
   strncat(event_data, "</url>", 6);
   event_data_length = strlen(event_data);

   total_str_length += event_data_length;

   /*
      Now construct the FineLine event record.
   */
   strncpy(event_string, "<event><id>", 11);
   strncat(event_string, "0000", 4);
   strncat(event_string, "</id><evidencenumber>NONE</evidencenumber><time>", 48);
   strncat(event_string, flurl->url_time_string, 32);
   strncat(event_string, "</time><type>Internet Explorer 10+</type><summary>", 50); 
   strncat(event_string, url_tld, strlen(url_tld));
   strncat(event_string, "</summary><data>", 16);
   strncat(event_string, event_data, event_data_length); 
   strncat(event_string, "</data><hiddenevent>0</hiddenevent><hiddentext>0</hiddentext><marked>0</marked><pinned>0</pinned><ypos>0</ypos></event>\n", 120);
   total_str_length += 192;

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

/*
   Function: get_access_count()

   Purpose : Extracts the access count value from the URL record and copies it
             to the FineLine URL record.
   Input   : libesed webcachev01.dat table record from the History table.
   Output  : Returns status value.

*/
int get_access_count(libesedb_record_t *record, int column, int column_type, struct fl_url_record *flurl)
{
   libcerror_error_t *error    = NULL;
   uint16_t value_16bit       = 0;
   uint32_t value_32bit       = 0;
   uint64_t value_64bit       = 0;
   int result = 0;

   switch( column_type )
   {
      case LIBESEDB_COLUMN_TYPE_INTEGER_16BIT_SIGNED:
      case LIBESEDB_COLUMN_TYPE_INTEGER_16BIT_UNSIGNED:
           result = libesedb_record_get_value_16bit(record, column, &value_16bit, &error);
           flurl->access_count = (uint64_t) value_16bit;
           break;
      case LIBESEDB_COLUMN_TYPE_INTEGER_32BIT_SIGNED:
      case LIBESEDB_COLUMN_TYPE_INTEGER_32BIT_UNSIGNED:
           result = libesedb_record_get_value_32bit(record, column, &value_32bit, &error);
           flurl->access_count = (uint64_t) value_32bit;
           break;
      case LIBESEDB_COLUMN_TYPE_INTEGER_64BIT_SIGNED:
           result = libesedb_record_get_value_64bit(record, column, &value_64bit, &error);
           flurl->access_count = value_64bit;
           break;
      default:
           result = -1;
   }

   return(result);
}

/*
   Function: get_record_index()

   Purpose : Extracts the record id from the URL record and copies it to the
             FineLine URL record, this value must be globally unique as it is
             used as the key value in the URL hashmap.
   Input   : libesed webcachev01.dat table record from the history table.
   Output  : Returns status value.

*/
int get_record_index(libesedb_record_t *record, int column, int column_type, struct fl_url_record *flurl)
{
   libcerror_error_t *error   = NULL;
   uint16_t value_16bit       = 0;
   uint32_t value_32bit       = 0;
   uint64_t value_64bit       = 0;
   int result = 0;

   switch( column_type )
   {
      case LIBESEDB_COLUMN_TYPE_INTEGER_16BIT_SIGNED:
      case LIBESEDB_COLUMN_TYPE_INTEGER_16BIT_UNSIGNED:
           result = libesedb_record_get_value_16bit(record, column, &value_16bit, &error);
           flurl->id = (int) value_16bit;
           break;
      case LIBESEDB_COLUMN_TYPE_INTEGER_32BIT_SIGNED:
      case LIBESEDB_COLUMN_TYPE_INTEGER_32BIT_UNSIGNED:
           result = libesedb_record_get_value_32bit(record, column, &value_32bit, &error);
           flurl->id = (int) value_32bit;
           break;
      case LIBESEDB_COLUMN_TYPE_INTEGER_64BIT_SIGNED:
           result = libesedb_record_get_value_64bit(record, column, &value_64bit, &error);
           flurl->id = (int)value_64bit;
           break;
      default:
           result = -1;
   }

   return(result);
}

/*
   Function: get_date_time_string()

   Purpose : Extracts the last access time from the URL record and converts it to a
             string and copies the string to the FineLine URL record. Also copies
             the 64bit time value to the FineLine URL record for later sorting the
             URL hashmap into time sequence order.
   Input   : libesed webcachev01.dat table record for the Containers table.
   Output  : Returns status value.

*/
int get_date_time_string(libesedb_record_t *record, int column, struct fl_url_record *flurl)
{
   libcerror_error_t *error                          = NULL;
   libfdatetime_filetime_t *filetime                 = NULL;
   libfdatetime_date_time_values_t *date_time_values = NULL;
   uint64_t value_64bit = 0;
   int result;

   result = libesedb_record_get_value_filetime(record, column, &value_64bit, &error);

   if( result == -1 )
   {
      /* we have a problem getting datetime values from the record!!! */
      result = libesedb_record_get_value_64bit(record, column, &value_64bit, &error);
      if( result == -1 )
      {
         print_log_entry("get_date_time_string() <ERROR> Could not get 64bit file time.\n");
         return( -1 ); 
      }
   }

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

   if(libfdatetime_filetime_copy_from_64bit(filetime, value_64bit, &error) != 1)
   {
      print_log_entry("get_date_time_string() <ERROR> Could not copy file time.\n");
      return(-1);
   }

   flurl->url_time = (double) value_64bit; /* this will be used later to sort the hashmap into time sequence order */

   if (libfdatetime_filetime_copy_to_date_time_values((libfdatetime_internal_filetime_t *)filetime, date_time_values, &error ) != 1)
   {
      print_log_entry("get_date_time_string() <ERROR> Could not get event date and time values.\n");
      return(-1);
   }

   /* FineLine date/time format is DD/MM/YYYY HH:MM:SS */
   sprintf(flurl->url_time_string, "%02d/%02d/%04d %02d:%02d:%02d", date_time_values->day, date_time_values->month, date_time_values->year, date_time_values->hours, date_time_values->minutes, date_time_values->seconds);

   flurl->year = date_time_values->year;
   flurl->month = date_time_values->month;
   flurl->day = date_time_values->day;

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

/*
   Function: get_table_index()

   Purpose : Extracts the 64bit integer value of the table index from the table record,
             the table index is the first value in the record (0).
   Input   : libesed webcachev01.dat table record for the Containers table.
   Output  : Returns status value.

*/

int get_table_index(libesedb_file_t *input_file, libesedb_record_t *container_record, int id_column)
{
   libesedb_table_t *table    = NULL;
   libcerror_error_t *error   = NULL;
   uint8_t *value_data        = NULL;
   size_t value_data_size     = 0;
   uint8_t value_flags        = 0;
   uint32_t column_type       = 0;
   uint8_t  value_8bit        = 0;
   uint16_t value_16bit       = 0;
   uint32_t value_32bit       = 0;
   uint64_t value_64bit       = 0;
   int table_index            = 0;
   int container_id           = 0;
   int result                 = 0;
   int number_of_tables       = 0;
   size_t table_name_size     = 0;
   char *table_name;
   char container_name[32];

   if(libesedb_record_get_column_type(container_record, id_column, &column_type, &error) != 1)
   {
      print_log_entry("get_table_index() <ERROR> Could not get column index.\n");
      return(-1);
   }
   if(libesedb_record_get_value(container_record, id_column, &value_data, &value_data_size, &value_flags, &error) != 1)
   {
      print_log_entry("get_table_index() <ERROR> Could not get record value.\n");
      return(-1);
   }
   if((value_flags & ~(LIBESEDB_VALUE_FLAG_VARIABLE_SIZE)) == 0)
   {
      switch(column_type)
      {
         case LIBESEDB_COLUMN_TYPE_BOOLEAN: 
              printf("get_table_index() Index type = boolean\n"); break;

         case LIBESEDB_COLUMN_TYPE_INTEGER_8BIT_UNSIGNED: 
              printf("get_table_index() Index type = 8bit\n"); 
              result = libesedb_record_get_value_8bit(container_record, id_column, &value_8bit, &error); 
              container_id = (int) value_8bit; break;

         case LIBESEDB_COLUMN_TYPE_INTEGER_16BIT_SIGNED: 
         case LIBESEDB_COLUMN_TYPE_INTEGER_16BIT_UNSIGNED: 
              printf("get_table_index() Index type = 16bit\n"); 
              result = libesedb_record_get_value_16bit(container_record, id_column, &value_16bit, &error); 
              container_id = (int) value_16bit; break;

         case LIBESEDB_COLUMN_TYPE_INTEGER_32BIT_SIGNED:
         case LIBESEDB_COLUMN_TYPE_INTEGER_32BIT_UNSIGNED: 
              printf("get_table_index() Index type = 32bit\n"); 
              result = libesedb_record_get_value_32bit(container_record, id_column, &value_32bit, &error); 
              container_id = (int) value_32bit; break;

         case LIBESEDB_COLUMN_TYPE_INTEGER_64BIT_SIGNED: 
              printf("get_table_index() Index type = 64bit\n"); 
              result = libesedb_record_get_value_64bit(container_record, id_column, &value_64bit, &error); 
              container_id = (int) value_64bit; break;

         case LIBESEDB_COLUMN_TYPE_DATE_TIME: 
              printf("get_table_index() Index type = datetime\n"); break;

         case LIBESEDB_COLUMN_TYPE_TEXT: 
              printf("get_table_index() Index type = text\n"); break;

         case LIBESEDB_COLUMN_TYPE_LARGE_TEXT: 
              printf("get_table_index() Index type = large text\n"); break;

         default:
            table_index = -1;
            printf("get_table_index() unknown type\n");
      }
   }

   if (result != 1)
   {
      print_log_entry("get_table_index() <ERROR> Could not get Container table id value.\n");
      return(-1);
   }

   sprintf(container_name, "Container_%d", container_id);
   printf("get_table_index() <INFO> Container Id = %d\n", container_id);

   if(libesedb_file_get_number_of_tables(input_file, &number_of_tables, &error) != 1)
   {
      print_log_entry("get_table_index() <ERROR> Could not get number of tables in cache file.\n");
      return(-1);
   }
   for(table_index = 0; table_index < number_of_tables; table_index++)
   {
      if(libesedb_file_get_table(input_file, table_index, &table, &error) != 1)
      {
         print_log_entry("parse_ie_cache_file() <ERROR> Could not get table.\n");
         return(-1);
      }
      if(libesedb_table_get_utf8_name_size(table, &table_name_size, &error) != 1)
      {
         print_log_entry("parse_ie_cache_file() <ERROR> Could not get table name size.\n");
         return(-1);
      }
      if(table_name_size > 0 )
      {
         table_name = (char *) xcalloc(table_name_size);
         if (libesedb_table_get_utf8_name(table, (uint8_t *) table_name, table_name_size, &error) != 1)
         {
            print_log_entry("parse_ie_cache_file() <ERROR> Could not get table name.\n");
            return(-1);
         }
      }

      if (strncmp(table_name, container_name, strlen(container_name)) == 0)
      {
         printf("get_table_index() <INFO> Found table : %s\n", table_name);
         if(libesedb_table_free(&table, &error) != 1)
         {
            print_log_entry("parse_ie_cache_file() <ERROR> Could not free table.\n");
            return(-1);
         }
         xfree(table_name, table_name_size);
         break;
      }
      if(libesedb_table_free(&table, &error) != 1)
      {
         print_log_entry("parse_ie_cache_file() <ERROR> Could not free table.\n");
         return( -1 );
      }
      xfree(table_name, table_name_size);
   }

   return(table_index);

}

/*
   Function: get_container_id_column()

   Purpose : Iterates of the Container table columns to find the ContainerId column number,
             this is normally = 0.
   Input   : libesed webcachev01.dat table record for the Containers table.
   Output  : Returns status value.

*/
int get_container_id_column(libesedb_table_t *table)
{
   libcerror_error_t *error   = NULL;
   libesedb_column_t *column = NULL;
   int number_of_columns  = 0;
   int column_iterator    = 0;
   size_t value_string_size  = 0;
   char *value_string;

   if(libesedb_table_get_number_of_columns(table, &number_of_columns, 0, &error) != 1 )
   {
      print_log_entry("get_container_id_column() <ERROR> Could not get number of columns.\n");
      return(-1);
   }
   for(column_iterator = 0; column_iterator < number_of_columns; column_iterator++)
   {
      if(libesedb_table_get_column(table, column_iterator, &column, 0, &error) != 1)
      {
         print_log_entry("get_container_id_column() <ERROR> Could not get column.\n");
         return(-1);
      }
      if(libesedb_column_get_utf8_name_size(column, &value_string_size, &error) != 1)
      {
         print_log_entry("get_container_id_column() <ERROR> Could not get column name size.\n");
         return(-1);
      }
      if(value_string_size == 0)
      {
         print_log_entry("get_container_id_column() <ERROR> Column name size = 0.\n");
         return(-1);
      }
      value_string = (char*)xcalloc(value_string_size);
      if(libesedb_column_get_utf8_name(column, (uint8_t *) value_string, value_string_size, &error) != 1)
      {
         print_log_entry("get_container_id_column() <ERROR> Could not get column name.\n");
         return(-1);
      }
      
      if (strncmp(value_string, "ContainerId", 11) == 0)
      {
         printf("get_container_id_column() <INFO> Container ID column = %d\n", column_iterator);
         xfree(value_string, value_string_size);
         if(libesedb_column_free(&column, &error) != 1)
         {
            print_log_entry("get_container_id_column() <ERROR> Could not freee column.\n");
            return(-1);
         }
         break;
      }

      xfree(value_string, value_string_size);
      if(libesedb_column_free(&column, &error) != 1)
      {
         print_log_entry("get_container_id_column() <ERROR> Could not freee column.\n");
         return(-1);
      }
   }

   return(column_iterator);
}

int process_cache_table(libesedb_table_t *table)
{
   print_log_entry("parse_ie_cache_file() <INFO> Processing History Table.\n");
   return(0);
}

int process_cache_url_item(char *url_item)
{
   print_log_entry("process_url_item() <INFO> Processed URL item.\n");
   return(0);
}

int process_cache_record(libesedb_record_t *record, FILE *out_file)
{
   libcerror_error_t *error;
   int number_of_values  = 0;
   int value_iterator    = 0;

   if( record == NULL )
   {
      print_log_entry("process_cache_record() <ERROR> Record is null.\n");
      return( -1 );
   }

   if( libesedb_record_get_number_of_values(record, &number_of_values, &error) != 1 )
   {
      print_log_entry("process_cache_record() <ERROR> Record is null.\n");
      return( -1 );
   }
   for(value_iterator = 0; value_iterator < number_of_values; value_iterator++ )
   {

      if( value_iterator == ( number_of_values - 1 ) )
      {
		
      }
      else
      {
			
      }
   }
   return(0);
}



/* DEPRECATED - use process_history_table() instead
   Function: process_iedownload_table()

   Purpose : Iterates over the records in the iedownload table and outputs the URL, last access time and
             access count for each record.
   Input   : libesed webcachev01.dat file pointer, iedownload table record for the Containers table.
   Output  : Returns status value.

*/

int process_iedownload_table(libesedb_file_t *input_file, libesedb_record_t *container_record, int id_column)
{
   libcerror_error_t *error   = NULL;
   libesedb_record_t *record  = NULL;
   libesedb_table_t  *table   = NULL;
   int number_of_records  = 0;
   int number_of_values   = 0;
   int record_iterator    = 0;
   int value_iterator     = 0;
   size_t value_string_size  = 0;
   size_t value_data_size = 0;
   uint8_t value_flags    = 0;
   uint32_t column_type   = 0;
   char *value_string;
   uint8_t *value_data = NULL;
   int table_index;
  

   print_log_entry("process_iedownload_table() <INFO> Processing iedownload Table.\n");

   table_index = get_table_index(input_file, container_record, id_column);
   if (table_index < 0)
   {
      print_log_entry("parse_iedownload_table() <ERROR> Could not get table index.\n");
      return(-1);
   }

   if(libesedb_file_get_table(input_file, table_index, &table, &error) != 1)
   {
      print_log_entry("parse_iedownload_table() <ERROR> Could not get table.\n");
      return(-1);
   }

   if(libesedb_table_get_number_of_records(table, &number_of_records, &error) != 1)
   {
      print_log_entry("process_iedownload_table() <ERROR> Could not get number of records.\n");
      return(-1);
   }

   printf("process_iedownload_table() <INFO> Processing %d records.\n", number_of_records);

   for(record_iterator = 0; record_iterator < number_of_records; record_iterator++)
   {
      if(libesedb_table_get_record(table, record_iterator, &record, &error) != 1)
      {
         print_log_entry("process_iedownload_table() <ERROR> Could not get record.\n");
         return(-1);
      }

      /* now iterate of the record values and print out */
      if(libesedb_record_get_number_of_values(record, &number_of_values, &error ) != 1)
      {
         print_log_entry("process_iedownload_table() <ERROR> Could not get number of values.\n");
         return( -1 );
      }
      for(value_iterator = 0; value_iterator < number_of_values; value_iterator++)
      {
         if(libesedb_record_get_column_type(record, value_iterator, &column_type, &error) != 1)
	 {
            print_log_entry("process_iedownload_table() <ERROR> Could not get column type.\n");            
            return( -1 );
	 }
         if(libesedb_record_get_value(record, value_iterator, &value_data, &value_data_size, &value_flags, &error) != 1)
         {
            print_log_entry("process_iedownload_table() <ERROR> Could not get record value.\n");
            return(-1);
         }
         if ((column_type == LIBESEDB_COLUMN_TYPE_TEXT) || (column_type == LIBESEDB_COLUMN_TYPE_LARGE_TEXT))
         {
            if (libesedb_record_get_value_utf8_string_size(record, value_iterator, &value_string_size, &error) < 0)
            {
               print_log_entry("process_iedownload_table() <ERROR> Could not get record value size.\n");
               return(-1);
            }
            value_string = (char *)xcalloc(value_string_size);
            if (libesedb_record_get_value_utf8_string(record, value_iterator, (uint8_t *)value_string, value_string_size, &error) != 1)
            {
               print_log_entry("process_iedownload_table() <ERROR> Could not get record value string.\n");
               return(-1);
            }
            printf("process_iedownload_table() <INFO> Found Download : %s\n", value_string);
            xfree(value_string, value_string_size);
         }
      }
      if(libesedb_record_free(&record, &error) != 1)
      {
         print_log_entry("process_iedownload_table() <ERROR> Could not free record.\n");
         return( -1 );
      }
   }

   return(0);
}

