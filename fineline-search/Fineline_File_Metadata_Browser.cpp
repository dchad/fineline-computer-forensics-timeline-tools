


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



#include "Fineline_File_Metadata_Browser.h"

Fineline_File_Metadata_Browser::Fineline_File_Metadata_Browser(int x, int y, int w, int h) : Fl_Help_View(x, y, w, h)
{
   //ctor
}

Fineline_File_Metadata_Browser::~Fineline_File_Metadata_Browser()
{
   //dtor
}


int Fineline_File_Metadata_Browser::add_file_record(fl_file_record_t *flec)
{
   if (flec != NULL)
   {
      file_list.push_back(flec);
   }
   return(0);
}


int Fineline_File_Metadata_Browser::add_html_row(string file_metadata)
{
   return(0);
}


string Fineline_File_Metadata_Browser::get_html_row(int record_number)
{
   string row;

   return(row);
}

int Fineline_File_Metadata_Browser::delete_html_row(int record_number)
{
   return(0);
}

int Fineline_File_Metadata_Browser::add_html_table(string metadata_table)
{
   return(0);
}

string Fineline_File_Metadata_Browser::get_html_table()
{
   string table;

   return(table);
}

int Fineline_File_Metadata_Browser::delete_html_table()
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
