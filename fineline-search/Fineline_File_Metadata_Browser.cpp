
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
   Fineline_File_Metadata_Browser.cpp

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 25/05/2014

   Purpose: FineLine FLTK GUI file metadata browser widget.

   Notes: EXPERIMENTAL

*/

#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include "../common/Fineline_Util.h"
#include "Fineline_Log.h"

#include "Fineline_File_Metadata_Browser.h"

Fineline_File_Metadata_Browser::Fineline_File_Metadata_Browser(int x, int y, int w, int h) : Fl_Browser(x, y, w, h)
{
   //ctor
   textfont(FL_HELVETICA);
   textsize(10);
   textcolor(FL_DARK_BLUE);

   static int widths[] = { 100, 150, 150, 150, 100, 100, 100, 100, 100, 50, 0 };            // widths for each column
   column_widths(widths);
   column_char('\t');                                                       // tabs as column delimiters
   type(FL_MULTI_BROWSER);

   //resizable();
}

Fineline_File_Metadata_Browser::~Fineline_File_Metadata_Browser()
{
   //dtor
}


int Fineline_File_Metadata_Browser::add_file_record(fl_file_record_t *flec)
{
   char file_size_string[256];
   string meta_line;

   if (flec != NULL)
   {
      get_long_time_strings(flec);

      file_list.push_back(flec);

      if (size() == 0)
      {
         meta_line = "Filename\tModification Time\tAccess Time\tCreation Time\tOwner\tFile Size";
         add(meta_line.c_str());
      }

      meta_line = flec->file_name;

      meta_line.append("\t");
      meta_line.append(flec->file_modification_time_string);

      meta_line.append("\t");
      meta_line.append(flec->file_access_time_string);

      meta_line.append("\t");
      meta_line.append(flec->file_creation_time_string);

      meta_line.append("\t");
      meta_line.append(flec->file_owner);

      meta_line.append("\t");
      meta_line.append(Fineline_Util::xitoa(flec->file_size, file_size_string, 256, 10));

      //meta_line.append("\t");
      //meta_line.append("................................................................");


      add(meta_line.c_str());

      if (DEBUG)
         Fineline_Log::print_log_entry(meta_line.c_str());
   }
   return(0);
}

int add_file_record_list(vector< fl_file_record_t* > append_list)
{
   //TODO: add the records to the vector and call add_file_record() to format into html and display

   return(0);
}

int Fineline_File_Metadata_Browser::add_row(string file_metadata)
{
   return(0);
}


string Fineline_File_Metadata_Browser::get_row(int record_number)
{
   string row = text(record_number);

   return(row);
}

int Fineline_File_Metadata_Browser::delete_row(int record_number)
{
   return(0);
}

int Fineline_File_Metadata_Browser::add_table(string metadata_table)
{
   return(0);
}

string Fineline_File_Metadata_Browser::get_table()
{
   string table;

   return(table);
}

int Fineline_File_Metadata_Browser::delete_table()
{
   return(0);
}

string Fineline_File_Metadata_Browser::format_record_as_html(fl_file_record_t *flec)
{
   string row;

   return(row);
}

string Fineline_File_Metadata_Browser::format_record_as_xml(fl_file_record_t *flec)
{
   string row;

   return(row);
}

int Fineline_File_Metadata_Browser::get_record_count()
{
   return(file_list.size());
}

int Fineline_File_Metadata_Browser::get_long_time_strings(fl_file_record_t *flec)
{
   // Convert long time to strings
   time_t filetime;
   struct tm *loctime;
   char *time_str;

   /* Get the access time. */
   filetime = (time_t)flec->access_time;
   loctime = localtime (&filetime);
   time_str = asctime(loctime);
   Fineline_Util::rtrim(time_str);
   strncpy(flec->file_access_time_string, time_str, strlen(time_str));

   /* Get the modification time. */
   filetime = (time_t)flec->modification_time;
   loctime = localtime (&filetime);
   time_str = asctime(loctime);
   Fineline_Util::rtrim(time_str);
   strncpy(flec->file_modification_time_string, time_str, strlen(time_str));

   /* Get the creation time. */
   filetime = (time_t)flec->creation_time;
   loctime = localtime (&filetime);
   time_str = asctime(loctime);
   Fineline_Util::rtrim(time_str);
   strncpy(flec->file_creation_time_string, time_str, strlen(time_str));

   return(0);
}

int Fineline_File_Metadata_Browser::save_metadata_list(const char *filename)
{
   //TODO: open or create a text file and write out the file metadata list
   return(0);
}
