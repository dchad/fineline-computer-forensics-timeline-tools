

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
   Fineline_Report_Dialog.h

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 10/05/2014

   Purpose: FineLine FLTK GUI dialog to add file metadata to the case/project report.

   Notes: EXPERIMENTAL

*/

#ifndef FINELINE_REPORT_DIALOG_H
#define FINELINE_REPORT_DIALOG_H

#include <stdio.h>
#include <vector>
#include <string>

#include <FL/Fl.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Browser.H>
#include <FL/Fl_Box.H>
#include <FL/filename.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Native_File_Chooser.H>
#include <FL/Fl_Text_Editor.H>
#include <FL/Fl_Text_Buffer.H>

#include "fineline-search.h"

using namespace std;

class Fineline_Report_Dialog : public Fl_Double_Window
{

   public:
      Fineline_Report_Dialog(int x, int y, int w, int h);
      virtual ~Fineline_Report_Dialog();

      static void button_callback(Fl_Button *b, void *p);

      static void put_file_metadata(fl_file_record_t *flrec);

      static void delete_cb(Fl_Widget *w, void *v);
      static void paste_cb(Fl_Widget *w, void *v);
      static void copy_cb(Fl_Widget *w, void *v);
      static void cut_cb(Fl_Widget *w, void *v);
      static void find_cb(Fl_Widget *w, void *v);
      static void find_next_cb(Fl_Widget *w, void *v);
      static void replace_cb(Fl_Widget *w, void *v);
      static void replace_next_cb(Fl_Widget *w, void *v);
      static void quit_cb(Fl_Widget *w, void *v);
      static void close_cb(Fl_Widget *w, void *v);
      static void open_cb(Fl_Widget *w, void *v);
      static void save_cb(Fl_Widget *w, void *v);
      static void saveas_cb(Fl_Widget *w, void *v);
      static void insert_cb(Fl_Widget *w, void *v);

      void add_metadata(string metadata);
      void add_metadata_file(string filename);
      void clear_metadata();
      void add_marked_files(vector< fl_file_record_t* > flist);

   protected:
   private:

      vector< fl_file_record_t* > marked_file_list;
      Fl_Text_Editor *teditor;
      Fl_Text_Buffer *text_buffer;
      FILE *report_file;
};

#endif // FINELINE_REPORT_DIALOG_H
