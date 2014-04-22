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
   flsearchcacheparser.c

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 02/03/2014

   Purpose: Analyses Windows search database files (windows.edb)
            and outputs the files in FineLine Event format.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fineline-ws.h"

#include <libfdatetime_date_time_values.h>
#include <libfdatetime_definitions.h>
#include <libfdatetime_error.h>
#include <libfdatetime_fat_date_time.h>
#include <libfdatetime_filetime.h>
#include <libfdatetime_nsf_timedate.h>
#include <libfdatetime_posix_time.h>
#include <libfdatetime_types.h>

/*
   Function: process_winsearch_cache_file()

   Purpose : Opens the output file/socket then iterates over the tables in Windows.edb file and finds the system index
             table. The system index table contains a record of every file on the system.
   Input   : Windows.edb file, output filename, mode, GUI IP address and filter filename.
   Output  : Returns status value.

*/

int parse_winsearch_cache_file(char *winsearchfile, char *fl_event_filename, int mode, char *gui_ip_addr, char *filter_filename)
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
      print_log_entry("parse_winsearch_cache_file() <ERROR> Could not initialise input file.\n");
      return(-1);
   }

   if(libesedb_file_open(input_file, winsearchfile, LIBESEDB_OPEN_READ, &error) != 1)
   {
      print_log_entry("parse_winsearch_cache_file() <ERROR> Could not open input file.\n");
      return(-1);
   }

   /*
      Now get the number of tables in the cache file, we specifically want the
      SystemIndex_0A table for Win7 and earlier and SystemIndex_PropertyStore for Win8.
      This table contains a record of every file in the filesystem that has been indexed.
   */

   if(libesedb_file_get_number_of_tables(input_file, &number_of_tables, &error ) != 1)
   {
      print_log_entry("parse_winsearch_cache_file() <ERROR> Could not get number of tables in cache file.\n");
      return(-1);
   }
   if( number_of_tables == 0 )
   {
      print_log_entry("parse_winsearch_cache_file() <INFO> No tables in cache file.\n");
      return( 0 );
   }

   printf("parse_winsearch_cache_file() <INFO> Number of tables: %d.\n", number_of_tables);

   /* if -w mode then open the fineline event file for output */
   if (mode & FL_FILE_OUT)
   {
      fl_evt_file = open_fineline_event_file(fl_event_filename);

      if (fl_evt_file == NULL)
      {
         print_log_entry("parse_winsearch_cache_file() <ERROR> Failed to open FineLine event file.\n");
         return(-1);
      }
   }
   /* if -s mode then create the socket to the GUI */
   if (mode & FL_GUI_OUT)
   {
      if (init_socket(gui_ip_addr))
      {
         print_log_entry("parse_winsearch_cache_file() <ERROR> Could not open socket to GUI.\n");
         return(-1);
      }
      /* TODO: send_fineline_project_header("NEW PROJECT", fl_evt_file); */
   }
   /* if -f mode then open the filter file */
   if (mode & FL_FILTER_ON)
   {
      if (load_file_filters(filter_filename) < 0)
      {
         print_log_entry("parse_winsearch_cache_file() <ERROR> Could not load URL filter file.\n");
         return(-1);
      }
   }

   for(table_index = 0; table_index < number_of_tables; table_index++)
   {
      if(libesedb_file_get_table(input_file, table_index, &table, &error) != 1 )
      {
         print_log_entry("parse_winsearch_cache_file() <ERROR> Could not get table.\n");
         return(-1);
      }
      if(libesedb_table_get_utf8_name_size(table, &table_name_size, &error) != 1)
      {
         print_log_entry("parse_winsearch_cache_file() <ERROR> Could not get table name size.\n");
         return(-1);
      }
      if(table_name_size > 0 )
      {
         table_name = (char *)xcalloc(table_name_size);
         if (libesedb_table_get_utf8_name(table, (uint8_t *) table_name, table_name_size, &error) != 1)
         {
            print_log_entry("parse_winsearch_cache_file() <ERROR> Could not get table name.\n");
            return(-1);
         }
      }
      /* printf("parse_winsearch_cache_file() <INFO> Found table: %s\n", table_name); */

      if (strncmp(table_name, "SystemIndex_0A", 14) == 0)
      {
         /*
           This is the Windows 7/Vista/XP SystemIndex_0A table, now parse it to found the records
           for all the indexed files.
         */
         if(process_systemindex_table(table, mode) < 0)
         {
            print_log_entry("parse_winsearch_cache_file() <ERROR> Could not process systemindex table.\n");
            return(-1);
         }
         else
         {
            sort_by_time();
            if (mode & FL_FILE_OUT)
            {
               write_file_map(fl_evt_file);
            }

            if (mode & FL_GUI_OUT)
            {
               send_file_map();
            }
         }
      }
      else if (strncmp(table_name, "SystemIndex_PropertyStore", 25) == 0)
      {
         /*
            This is the Windows 8 properties table, so parse it and generate event records
            for each indexed file.
         */
         if(process_systemindex_propertystore_table(table, mode) < 0)
         {
            print_log_entry("parse_winsearch_cache_file() <ERROR> Could not process property store table.\n");
            return(-1);
         }
         else
         {
            sort_by_time();
            if (mode & FL_FILE_OUT)
            {
               write_file_map(fl_evt_file);
            }

            if (mode & FL_GUI_OUT)
            {
               send_file_map();
            }
         }
      }
      if(libesedb_table_free(&table, &error) != 1)
      {
         print_log_entry("parse_winsearch_cache_file() <ERROR> Could not free table.\n");
         return( -1 );
      }
      xfree(table_name, table_name_size);
   }

   if(libesedb_file_close(input_file, &error) != 0)
   {
      print_log_entry("parse_winsearch_cache_file() <ERROR> Could not close input file.\n");
      return(-1);
   }

   if(libesedb_file_free(&input_file, &error) != 1)
   {
      print_log_entry("parse_winsearch_cache_file() <ERROR> Could not free input file.\n");
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
   Function: process_systemindex_table()

   Purpose : Iterates over the records in the SystemIndex_0A table and outputs the file name,
             creation time, last access time and access count for each record.
   Input   : Windows XP,Vista,7 SystemIndex_01 table record.
   Output  : Returns status value.

*/

int process_systemindex_table(libesedb_table_t *table, int mode)
{
   libcerror_error_t *error   = NULL;
   libesedb_record_t *record  = NULL;
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
   uint8_t *value_data                = NULL;
   struct fl_file_record *file_record = NULL;

   print_log_entry("process_systemindex_table() <INFO> Processing SystemIndex_0A Table.\n");

   /*
      Parse the table records and extract the following values, most of these seem to be common
      to Windows XP, Vista and 7.

      DocID : Integer32
      System_ItemName : Text
      System_ItemPath : Text
      System_DateAccessed : 64bit big endian integer
      System_DateModified : 64bit big endian integer
      System_DateCreated  : 64bit big endian integer
      System_ItemFolderNameDisplay : ?
      System_ItemFolderPathDisplay : ?
      System_FileOwner : Text             DEPRECATED: only null values.
      System_ItemNameDisplay : Text       DEPRECATED: only null values.
      System_ItemPathDisplay : Text       DEPRECATED: only null values.
      System_FileName : Text              DEPRECATED: only null values.
      System_Search_AccessCount : ?
      Microsoft_IE_VisitCount : Integer32 DEPRECATED: only 0.
      Microsoft_IE_TargetUrl : Text
      Microsoft_IE_Title : Text
      Microsoft_IE_SelectionCount : Integer32

   */


   if(libesedb_table_get_number_of_records(table, &number_of_records, &error) != 1)
   {
      print_log_entry("process_systemindex_table() <ERROR> Could not get number of records.\n");
      return(-1);
   }

   printf("process_systemindex_table() <INFO> Processing %d records.\n", number_of_records);

   for(record_iterator = 0; record_iterator < number_of_records; record_iterator++)
   {
      if(libesedb_table_get_record(table, record_iterator, &record, &error) != 1)
      {
         print_log_entry("process_systemindex_table() <ERROR> Could not get record.\n");
         return(-1);
      }

      /* now iterate of the record values and print out */
      if(libesedb_record_get_number_of_values(record, &number_of_values, &error ) != 1)
      {
         print_log_entry("process_systemindex_table() <ERROR> Could not get number of values.\n");
         return( -1 );
      }

      file_record = (struct fl_file_record *) xcalloc(sizeof(struct fl_file_record));

      for(value_iterator = 0; value_iterator < number_of_values; value_iterator++)
      {
         if(libesedb_record_get_column_type(record, value_iterator, &column_type, &error) != 1)
	      {
            print_log_entry("process_systemindex_table() <ERROR> Could not get column type.\n");
            return( -1 );
	      }
         if(libesedb_record_get_value(record, value_iterator, &value_data, &value_data_size, &value_flags, &error) != 1)
         {
            print_log_entry("process_systemindex_table() <ERROR> Could not get record value.\n");
            return(-1);
         }
         if(libesedb_record_get_utf8_column_name_size(record, value_iterator, &utf8_string_size, &error ) < 0)
         {
            print_log_entry("process_systemindex_table() <ERROR> Could not get column name size.\n");
            return(-1);
         }
         utf8_string = (char *)xcalloc(utf8_string_size);
         if(libesedb_record_get_utf8_column_name(record, value_iterator, (uint8_t *)utf8_string, utf8_string_size, &error) != 1)
         {
            print_log_entry("process_systemindex_table() <ERROR> Could not get column name.\n");
            return(-1);
         }

         if ((column_type == LIBESEDB_COLUMN_TYPE_TEXT) || (column_type == LIBESEDB_COLUMN_TYPE_LARGE_TEXT))
         {
            if (strncmp(utf8_string, "System_ItemName", 15) == 0)
            {
               if (get_file_name_string(record, value_iterator, file_record) < 0)
               {
                  print_log_entry("process_systemindex_table() <ERROR> Could not get file name string.\n");

               }
            }
            else if (strncmp(utf8_string, "System_FileOwner", 16) == 0)
            {
               if (get_file_owner_string(record, value_iterator, file_record) < 0)
               {
                  strncpy(file_record->file_owner, "UNKNOWN", 7);
               }
            }
            else if (strncmp(utf8_string, "System_ItemPath", 15) == 0) /* TODO: check which one is the actual file path */
            {
               if (get_file_path_string(record, value_iterator, file_record) < 0)
               {
                  print_log_entry("process_systemindex_table() <ERROR> Could not get file path string.\n");

               }
            }
         }
         else /* value is not a string so check for the numeric values */
         {
            if (strncmp(utf8_string, "DocID", 5) == 0) /* we have the record identifier */
            {
               /* get the record id and use as the hashmap id because they are unique keys in the url table */
               if (get_record_index(record, value_iterator, column_type, file_record) < 0)
               {
                  print_log_entry("process_systemindex_table() <ERROR> Could not get record index.\n");
                  return(-1);
               }
            }
            else if (strncmp(utf8_string, "Microsoft_IE_VisitCount", 23) == 0) /* TODO: check this is correct value */
            {
               /* get the URL access count and add to the URL record */
               if (get_access_count(record, value_iterator, column_type, file_record) < 0)
               {
                  print_log_entry("process_systemindex_table() <ERROR> Could not get URL access count.\n");
                  /* not a fatal error */
               }
            }
            else if(strncmp(utf8_string, "System_DateAccessed", 19) == 0)
            {
               /* get the date and time string and add to the file record */
               if(get_date_time_string(record, value_iterator, FL_FILE_ACCESS_TIME, file_record) < 0)
               {
                  strncpy(file_record->file_access_time_string, "NONE", 4);
               }
            }
            else if(strncmp(utf8_string, "System_DateModified", 19) == 0)
            {
               /* get the date and time string and add to the URL record */
               if(get_date_time_string(record, value_iterator, FL_FILE_MODIFY_TIME, file_record) < 0)
               {
                  strncpy(file_record->file_modification_time_string, "NONE", 4);
               }
            }
            else if(strncmp(utf8_string, "System_DateCreated", 18) == 0)
            {
               /* get the date and time string and add to the URL record */
               if(get_date_time_string(record, value_iterator, FL_FILE_CREATION_TIME, file_record) < 0)
               {
                  strncpy(file_record->file_creation_time_string, "NONE", 4);
               }
            }
         }

         xfree(utf8_string, utf8_string_size);
      }

      if(libesedb_record_free(&record, &error) != 1)
      {
         print_log_entry("process_systemindex_table() <ERROR> Could not free record.\n");
         return(-1);
      }

      /* check filename filtering */
      if (mode & FL_FILTER_ON)
      {
         if (match_file_filter(file_record->file_name) > 0)
         {
            /* now add the file record to the file hashmap */
            format_file_event_string(file_record);
            add_file_record(file_record->id, file_record);
         }
         else
         {
            filtered_records++;
         }
      }
      else
      {
         /* now add the file record to the file hashmap */
         format_file_event_string(file_record);
         add_file_record(file_record->id, file_record);
      }

   } /* for loop record iterator */

   printf("process_systemindex_table() <INFO> Processed %d records, filtered out %d records.\n", number_of_records, filtered_records);

   return(0);
}

/*
   Function: process_systemindex_propertystore_table()

   Purpose : Iterates over the records in the Win8 property store table and outputs the file name,
             creation time, last access time and access count for each record.
   Input   : Windows 8 SysteIndex_PropertyStore table record.
   Output  : Returns status value.

*/

int process_systemindex_propertystore_table(libesedb_table_t *table, int mode)
{
   libcerror_error_t *error   = NULL;
   libesedb_record_t *record  = NULL;
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
   uint8_t *value_data                = NULL;
   struct fl_file_record *file_record = NULL;
   char last_access_time[32];

   print_log_entry("process_systemindex_propertystore_table() <INFO> Processing SystemIndex_0A Table.\n");

   /*
      Parse the table records and extract the following values, for some inexplicable reason
      the field names in the Windows 8 search db have had some arbitrary number prepended to them.

      1. WorkID
      2. 4276-System_ItemName
      3. System_ItemPath??? DEPRECATED: Cannot find this field
      4. 4476-Microsoft_IE_Title
      5. 4477-Microsoft_IE_VisitCount
      6. 4475-Microsoft_IE_TargetUrlPath
      7. 17F-System_DateAccessed
      8. 15F-System_DateModified
      9. 16F-System_DateCreated
      10. 3-System_ItemFolderNameDisplay
      11. 4274-System_ItemFolderPathDisplay
      12. 4242-System_FileOwner
      13. 4281-System_ItemPathDisplay
      14. 4277-System_ItemNameDisplay
      15. 11-System_FileName

   */

   if(libesedb_table_get_number_of_records(table, &number_of_records, &error) != 1)
   {
      print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get number of records.\n");
      return(-1);
   }

   printf("process_systemindex_propertystore_table() <INFO> Processing %d records.\n", number_of_records);

   for(record_iterator = 0; record_iterator < number_of_records; record_iterator++)
   {
      if(libesedb_table_get_record(table, record_iterator, &record, &error) != 1)
      {
         print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get record.\n");
         return(-1);
      }

      /* now iterate of the record values and print out */
      if(libesedb_record_get_number_of_values(record, &number_of_values, &error ) != 1)
      {
         print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get number of values.\n");
         return( -1 );
      }

      file_record = (struct fl_file_record *) xcalloc(sizeof(struct fl_file_record));

      for(value_iterator = 0; value_iterator < number_of_values; value_iterator++)
      {
         if(libesedb_record_get_column_type(record, value_iterator, &column_type, &error) != 1)
	      {
            print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get column type.\n");
            return( -1 );
	      }
         if(libesedb_record_get_value(record, value_iterator, &value_data, &value_data_size, &value_flags, &error) != 1)
         {
            print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get record value.\n");
            return(-1);
         }
         if(libesedb_record_get_utf8_column_name_size(record, value_iterator, &utf8_string_size, &error ) < 0)
         {
            print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get column name size.\n");
            return(-1);
         }
         utf8_string = (char *)xcalloc(utf8_string_size);
         if(libesedb_record_get_utf8_column_name(record, value_iterator, (uint8_t *)utf8_string, utf8_string_size, &error) != 1)
         {
            print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get column name.\n");
            return(-1);
         }

         if ((column_type == LIBESEDB_COLUMN_TYPE_TEXT) || (column_type == LIBESEDB_COLUMN_TYPE_LARGE_TEXT))
         {
            if (strncmp(utf8_string, "4276-System_ItemName", 20) == 0)
            {
               if (get_file_name_string(record, value_iterator, file_record) < 0)
               {
                  print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get URL string.\n");
                  return( -1 );
               }
            }
            else if (strncmp(utf8_string, "3-System_ItemFolderNameDisplay", 30) == 0)
            {
               if (get_file_name_string(record, value_iterator, file_record) < 0)
               {
                  print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get URL string.\n");
                  return( -1 );
               }
            }
         }
         else /* value is not a text filed so check binary values */
         {
            if (strncmp(utf8_string, "WorkID", 6) == 0) /* we have the record identifier */
            {
               /* get the record id and use as the hashmap id because they are unique keys in the url table */

               /* TODO: CHECK IF GLOBALLY UNIQUE!!! */
               if (get_record_index(record, value_iterator, column_type, file_record) < 0)
               {
                  print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get record index.\n");
                  return(-1);
               }
            }
            else if (strncmp(utf8_string, "4477-Microsoft_IE_VisitCount", 28) == 0)
            {
               /* get the URL access count and add to the URL record */
               if (get_access_count(record, value_iterator, column_type, file_record) < 0)
               {
                  print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get URL access count.\n");
                  /* not a fatal error */
               }
            }
            else if(strncmp(utf8_string, "17F-System_DateAccessed", 23) == 0)
            {
               /* get the date and time string and add to the file record */
               if(get_date_time_string(record, value_iterator, FL_FILE_ACCESS_TIME, file_record) < 0)
               {
                  print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get date time string.\n");
                  strncpy(last_access_time, "NONE", 4);
               }
            }
            else if(strncmp(utf8_string, "15F-System_DateModified", 23) == 0)
            {
               if(get_date_time_string(record, value_iterator, FL_FILE_MODIFY_TIME, file_record) < 0)
               {
                  print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get date time string.\n");
                  strncpy(last_access_time, "NONE", 4);
               }
            }
            else if(strncmp(utf8_string, "16F-System_DateCreated", 21) == 0)
            {
               if(get_date_time_string(record, value_iterator, FL_FILE_MODIFY_TIME, file_record) < 0)
               {
                  print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not get date time string.\n");
                  strncpy(last_access_time, "NONE", 4);
               }
            }
         }

         xfree(utf8_string, utf8_string_size);
      }

      if(libesedb_record_free(&record, &error) != 1)
      {
         print_log_entry("process_systemindex_propertystore_table() <ERROR> Could not free record.\n");
         return(-1);
      }

      /* check file name filtering */
      if (mode & FL_FILTER_ON)
      {
         if (match_file_filter(file_record->file_name) > 0)
         {
            /* now add the URL record to the url hashmap */
            format_file_event_string(file_record);
            add_file_record(file_record->id, file_record);
         }
         else
         {
            filtered_records++;
         }
      }
      else
      {
         /* now add file record to the file hashmap */
         format_file_event_string(file_record);
         add_file_record(file_record->id, file_record);
      }
   } /* for loop record iterator */

   printf("process_systemindex_propertystore_table() <INFO> Processed %d records, filtered out %d records.\n", number_of_records, filtered_records);

   return(0);
}

/*
   Function: get_file_path_string()

   Purpose : Extracts the file path string from the file record and copies it to
             the FineLine file record.
   Input   : libesed Windows.edb table record from the SystemIndex_0A table.
   Output  : Returns status value.

*/
int get_file_path_string(libesedb_record_t *record, int column, struct fl_file_record *flf)
{
   libcerror_error_t *error   = NULL;
   char *value_string;
   size_t value_string_size  = 0;

   if (libesedb_record_get_value_utf8_string_size(record, column, &value_string_size, &error) < 0)
   {
      print_log_entry("get_file_path_string() <ERROR> Could not get record value size.\n");
      return(-1);
   }

   if (value_string_size > 0)
   {
      value_string = (char *)xcalloc(value_string_size);
      if (libesedb_record_get_value_utf8_string(record, column, (uint8_t *)value_string, value_string_size, &error) != 1)
      {
         print_log_entry("get_file_path_string() <ERROR> Could not get record value string.\n");
         return(-1);
      }
      /*
         Now copy the file path string to the FineLine file record.
      */
      if (value_string_size < FL_MAX_INPUT_STR)
         strncpy(flf->file_path, value_string, value_string_size);
      else
         strncpy(flf->file_path, value_string, FL_MAX_INPUT_STR);

      xfree(value_string, value_string_size);
   }

   return(0);
}


/*
   Function: get_file_name_string()

   Purpose : Extracts the file name and path string from the file record and copies it to
             the FineLine file record.
   Input   : libesed Windows.edb table record from the SystemIndex_0A table.
   Output  : Returns status value.

*/
int get_file_name_string(libesedb_record_t *record, int column, struct fl_file_record *flf)
{
   libcerror_error_t *error   = NULL;
   char *value_string;
   size_t value_string_size  = 0;

   if (libesedb_record_get_value_utf8_string_size(record, column, &value_string_size, &error) < 0)
   {
      print_log_entry("get_file_name_string() <ERROR> Could not get record value size.\n");
      return(-1);
   }

   if (value_string_size > 0)
   {
      value_string = (char *)xcalloc(value_string_size);
      if (libesedb_record_get_value_utf8_string(record, column, (uint8_t *)value_string, value_string_size, &error) != 1)
      {
         print_log_entry("get_file_name_string() <ERROR> Could not get record value string.\n");
         return(-1);
      }
      /*
         Now copy the file path string to the FineLine file record.
      */
      if (value_string_size < 256)
         strncpy(flf->file_name, value_string, value_string_size);
      else
         strncpy(flf->file_name, value_string, 256);

      xfree(value_string, value_string_size);
   }

   return(0);
}

/*
   Function: get_file_owner_string()

   Purpose : Extracts the file owner from the file record and copies it to
             the FineLine file record.
   Input   : libesed Windows.edb table record from the SystemIndex_0A table.
   Output  : Returns status value.

*/
int get_file_owner_string(libesedb_record_t *record, int column, struct fl_file_record *flf)
{
   libcerror_error_t *error   = NULL;
   char *value_string;
   size_t value_string_size  = 0;

   if (libesedb_record_get_value_utf8_string_size(record, column, &value_string_size, &error) < 0)
   {
      print_log_entry("get_file_owner_string() <ERROR> Could not get record value size.\n");
      return(-1);
   }

   if (value_string_size > 0)
   {
      value_string = (char *)xcalloc(value_string_size);
      if (libesedb_record_get_value_utf8_string(record, column, (uint8_t *)value_string, value_string_size, &error) != 1)
      {
         print_log_entry("get_file_owner_string() <ERROR> Could not get record value string.\n");
         return(-1);
      }
      /*
         Now copy the file path string to the FineLine file record.
      */
      if (value_string_size < 256)
         strncpy(flf->file_owner, value_string, value_string_size);
      else
         strncpy(flf->file_owner, value_string, 256);

      xfree(value_string, value_string_size);
   }

   return(0);
}

/*
   Function: format_file_event_string()

   Purpose : Creates a FineLine event record from the file information.
   Input   : FineLine event record pointer.
   Output  : Returns status value.

*/
int format_file_event_string(struct fl_file_record *flf)
{
   char event_data[FL_MAX_INPUT_STR];
   char event_string[FL_MAX_INPUT_STR];
   char temp_str[32];
   int  event_data_length  = 0;
   int  file_string_length = 0;
   int  total_str_length   = 0;

   memset(event_data, 0, FL_MAX_INPUT_STR);
   memset(event_string, 0, FL_MAX_INPUT_STR);
   memset(temp_str, 0, 32);

   file_string_length = strlen(flf->file_path);

   /*
      Now construct the file record event data field.
   */

   strncpy(event_data, "<accesstime>", 12);
   strncat(event_data, flf->file_access_time_string, 32);
   strncat(event_data, "</accesstime><creationtime>", 27);
   strncat(event_data, flf->file_creation_time_string, 32);
   strncat(event_data, "</creationtime><modificationtime>", 33);
   strncat(event_data, flf->file_modification_time_string, 32);
   strncat(event_data, "</modificationtime><accesscount>", 32);
   strcat(event_data, xitoa((int)flf->access_count, temp_str, 32, 10));
   strncat(event_data, "</accesscount><filepath>", 24);
   if (file_string_length < (FL_MAX_INPUT_STR - 512))
   {
      strncat(event_data, flf->file_path, file_string_length);
   }
   else
   {
      strncat(event_data, flf->file_path, (FL_MAX_INPUT_STR - 512));
   }
   strncat(event_data, "</filepath><owner>", 18);
   strncat(event_data, flf->file_owner, strlen(flf->file_owner));
   strncat(event_data, "</owner>", 8);
   event_data_length = strlen(event_data);

   total_str_length += event_data_length;

   /*
      Now construct the FineLine event record.
   */
   strncpy(event_string, "<event><id>", 11);
   strncat(event_string, "0000", 4);
   strncat(event_string, "</id><evidencenumber>NONE</evidencenumber><time>", 48);
   strncat(event_string, flf->file_access_time_string, 32);
   strncat(event_string, "</time><type>Windows Search</type><summary>", 53);
   strncat(event_string, flf->file_name, strlen(flf->file_name));
   strncat(event_string, "</summary><data>", 16);
   strncat(event_string, event_data, event_data_length);
   strncat(event_string, "</data><hiddenevent>0</hiddenevent><hiddentext>0</hiddentext><marked>0</marked><pinned>0</pinned><ypos>0</ypos></event>\n", 120);
   total_str_length += 192;

   /* Maximum char count = */
   if (total_str_length < FL_MAX_INPUT_STR)
   {
      strncpy(flf->file_event_string, event_string, strlen(event_string));
   }
   else
   {
      strncpy(flf->file_event_string, event_string, FL_MAX_INPUT_STR);
   }

   return(0);
}

/*
   Function: get_access_count()

   Purpose : Extracts the access count value from the file record and copies it
             to the FineLine file record.
   Input   : libesed Windows.edb table record, column number, column type.
   Output  : Returns status value.

*/
int get_access_count(libesedb_record_t *record, int column, int column_type, struct fl_file_record *flf)
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
           flf->access_count = (int) value_16bit;
           break;
      case LIBESEDB_COLUMN_TYPE_INTEGER_32BIT_SIGNED:
      case LIBESEDB_COLUMN_TYPE_INTEGER_32BIT_UNSIGNED:
           result = libesedb_record_get_value_32bit(record, column, &value_32bit, &error);
           flf->access_count = (int) value_32bit;
           break;
      case LIBESEDB_COLUMN_TYPE_INTEGER_64BIT_SIGNED:
           result = libesedb_record_get_value_64bit(record, column, &value_64bit, &error);
           flf->access_count = (int)value_64bit;
           break;
      default:
           result = -1;
   }

   return(result);
}

/*
   Function: get_record_index()

   Purpose : Extracts the record id from the file record and copies it to the
             FineLine file record, this value must be globally unique as it is
             used as the key value in the file hashmap.
   Input   : libesed Windows.edb table record.
   Output  : Returns status value.

*/
int get_record_index(libesedb_record_t *record, int column, int column_type, struct fl_file_record *flf)
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
           flf->id = (int) value_16bit;
           break;
      case LIBESEDB_COLUMN_TYPE_INTEGER_32BIT_SIGNED:
      case LIBESEDB_COLUMN_TYPE_INTEGER_32BIT_UNSIGNED:
           result = libesedb_record_get_value_32bit(record, column, &value_32bit, &error);
           flf->id = (int) value_32bit;
           break;
      case LIBESEDB_COLUMN_TYPE_INTEGER_64BIT_SIGNED:
           result = libesedb_record_get_value_64bit(record, column, &value_64bit, &error);
           flf->id = (int) value_64bit;
           break;
      default:
           result = -1;
   }

   return(result);
}

/*
   Function: get_date_time_string()

   Purpose : Extracts the last access time from the file record and converts it to a
             string and copies the string to the FineLine file record.
   Input   : libesed Windows.edb table record.
   Output  : Returns status value.

*/
int get_date_time_string(libesedb_record_t *record, int column, int time_stamp_type, struct fl_file_record *flf)
{
   libcerror_error_t *error                          = NULL;
   libfdatetime_filetime_t *filetime                 = NULL;
   libfdatetime_date_time_values_t *date_time_values = NULL;
   uint64_t value_64bit              = 0;
   uint8_t *value_data               = NULL;
	size_t value_data_size            = 0;
	uint8_t value_flags               = 0;

   /* result = libesedb_record_get_value_filetime(record, column, &value_64bit, &error); */
      /* we have a problem getting datetime values from the record!!!
      result = libesedb_record_get_value_64bit(record, column, &value_64bit, &error); */

   if(libesedb_record_get_value(record, column, &value_data, &value_data_size, &value_flags, &error ) != 1)
   {
      print_log_entry("get_date_time_string() <ERROR> Could not get file time data.\n");
      return( -1 );
   }

   if (value_data_size > 0)
   {
      /* get the file time */
      if(libfdatetime_filetime_initialize(&filetime, &error) != 1)
      {
         print_log_entry("get_date_time_string() <ERROR> Could not initialise file time.\n");
         return(-1);
      }

      if (libfdatetime_date_time_values_initialize(&date_time_values, &error) != 1)
      {
         print_log_entry("get_date_time_string() <ERROR> Could not initialise date time values.\n");
         return(-1);
      }

      if(libfdatetime_filetime_copy_from_byte_stream(filetime, value_data, value_data_size, _BYTE_STREAM_ENDIAN_BIG, &error) != 1)
      {
         print_log_entry("get_date_time_string() <ERROR> Could not copy filetime from byte stream.\n");
         return(-1);
      }

      /* Search Timestamps

      Win 8 search timestamps are ???
      Win 7 search timestamps are big endian 64 bit integer.
      Vista search timestamps are little endian 64 bit integer.
      Win XP search timestamps are big endian 64 bit integer.

      The FILETIME structure represents the number of 100-nanosecond intervals since January 1, 1601. \
      The structure consists of two 32-bit values that combine to form a single 64-bit value.

      typedef struct _FILETIME {
        DWORD dwLowDateTime;
        DWORD dwHighDateTime;
      } FILETIME;


      Note that the FILETIME structure is based on 100-nanosecond intervals.
      It is helpful to define the following symbols when working with file times. For example:

      #define _SECOND ((int64) 10000000)
      #define _MINUTE (60 * _SECOND)
      #define _HOUR   (60 * _MINUTE)
      #define _DAY    (24 * _HOUR)

      ULONGLONG qwResult;

      // Copy the time into a quadword.
      qwResult = (((ULONGLONG) ft.dwHighDateTime) << 32) + ft.dwLowDateTime;

      // Add 30 days.
      qwResult += 30 * _DAY;

      // Copy the result back into the FILETIME structure.
      ft.dwLowDateTime  = (DWORD) (qwResult & 0xFFFFFFFF );
      ft.dwHighDateTime = (DWORD) (qwResult >> 32 );

		http://support.microsoft.com/kb/188768


      libfdatetime:

	   internal_filetime->upper = value_64bit >> 32;
	   internal_filetime->lower = value_64bit & 0x0ffffffffLL;


      */

      byte_stream_copy_to_uint64_big_endian(value_data, value_64bit);

      switch(time_stamp_type)
      {
         case FL_FILE_ACCESS_TIME: flf->access_time = (long) value_64bit; break; /* this will be used later to sort the hashmap into time sequence order */
         case FL_FILE_CREATION_TIME: flf->creation_time = (long) value_64bit; break;
         case FL_FILE_MODIFY_TIME: flf->modification_time = (long) value_64bit; break;
         default:
            print_log_entry("get_date_time_string() <ERROR> Invalide file time type.\n");
            return(-1);
      }

      if (libfdatetime_filetime_copy_to_date_time_values((libfdatetime_internal_filetime_t *)filetime, date_time_values, &error ) != 1)
      {
         print_log_entry("get_date_time_string() <ERROR> Could not get event date and time values.\n");
         return(-1);
      }

      /* FineLine date/time format is DD/MM/YYYY HH:MM:SS */

      switch(time_stamp_type)
      {
         case FL_FILE_ACCESS_TIME: sprintf(flf->file_access_time_string, "%02d/%02d/%04d %02d:%02d:%02d", date_time_values->day, date_time_values->month, date_time_values->year, date_time_values->hours, date_time_values->minutes, date_time_values->seconds); break;
         case FL_FILE_CREATION_TIME: sprintf(flf->file_creation_time_string, "%02d/%02d/%04d %02d:%02d:%02d", date_time_values->day, date_time_values->month, date_time_values->year, date_time_values->hours, date_time_values->minutes, date_time_values->seconds); break;
         case FL_FILE_MODIFY_TIME: sprintf(flf->file_modification_time_string, "%02d/%02d/%04d %02d:%02d:%02d", date_time_values->day, date_time_values->month, date_time_values->year, date_time_values->hours, date_time_values->minutes, date_time_values->seconds); break;
         default:
            print_log_entry("get_date_time_string() <ERROR> Invalide file time type.\n");
      }

      if(libfdatetime_filetime_free(&filetime, &error) != 1)
      {
         print_log_entry("get_date_time_string() <ERROR> Could not free filetime.\n");
      }

      if(libfdatetime_date_time_values_free(&date_time_values, &error) != 1)
      {
         print_log_entry("get_date_time_string() <ERROR> Could not free date time values.\n");
      }
   }

   return(0);
}

/* copied from from libesedb/common/byte_stream.h
#define byte_stream_copy_to_uint64_big_endian( byte_stream, value ) \
	( value )   = ( byte_stream )[ 0 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 1 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 2 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 3 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 4 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 5 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 6 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 7 ];

#define byte_stream_copy_to_uint64_little_endian( byte_stream, value ) \
	( value )   = ( byte_stream )[ 7 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 6 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 5 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 4 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 3 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 2 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 1 ]; \
	( value ) <<= 8; \
	( value )  |= ( byte_stream )[ 0 ];


	*/


