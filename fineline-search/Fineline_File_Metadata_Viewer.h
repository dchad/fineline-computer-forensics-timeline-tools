

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
   Fineline_File_Metadata_Viewer.h

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 25/05/2014

   Purpose: FineLine FLTK GUI file metadata as html widget.

   Notes: EXPERIMENTAL

*/



#ifndef FINELINE_FILE_METADATA_BROWSER_H
#define FINELINE_FILE_METADATA_BROWSER_H

#include <string>
#include <vector>

#include <FL/Fl.H>
#include <FL/Fl_Help_View.H>

#include "fineline-search.h"

using namespace std;

class Fineline_File_Metadata_Browser : public Fl_Help_View
{
   public:
      Fineline_File_Metadata_Browser(int x, int y, int w, int h);
      virtual ~Fineline_File_Metadata_Browser();

      int add_file_record(fl_file_record_t *flec);
      int add_file_record_list(vector< fl_file_record_t* > append_list);
      int add_html_row(string file_metadata);
      string get_html_row(int record_number);
      int delete_html_row(int record_number);
      int add_html_table(string metadata_table);
      string get_html_table();
      int delete_html_table();
      int get_record_count();

      static string format_record_as_html(fl_file_record_t *flec);
      static string format_record_as_xml(fl_file_record_t *flec);

   protected:
   private:

      int get_long_time_strings(fl_file_record_t *flec);

      vector< fl_file_record_t* > file_list;
      string html_line;

};

#endif // FINELINE_FILE_METADATA_BROWSER_H
