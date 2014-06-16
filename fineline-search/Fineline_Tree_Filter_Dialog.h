

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
   Fineline_Tree_Filter_Dialog.h

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 10/06/2014

   Purpose: FineLine FLTK GUI file system tree file filter dialog.

   Notes: EXPERIMENTAL

*/



#ifndef FINELINE_TREE_FILTER_DIALOG_H
#define FINELINE_TREE_FILTER_DIALOG_H

#include <map>
#include <string>

#include <FL/Fl.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Browser.H>
#include <FL/Fl_Text_Editor.H>
#include <FL/Fl_Box.H>
#include <FL/filename.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Native_File_Chooser.H>

#include "Fineline_File_System_Tree.h"
#include "fineline-search.h"

using namespace std;

class Fineline_Tree_Filter_Dialog : public Fl_Double_Window
{
   public:
      Fineline_Tree_Filter_Dialog(int x, int y, int w, int h);
      virtual ~Fineline_Tree_Filter_Dialog();

      static void button_callback(Fl_Button *b, void *p);
      void add_matched_file(string filepath);
      void show_dialog(Fineline_File_System_Tree *ffst);

   protected:
   private:

      Fl_Browser *progress_browser;
      Fl_Text_Editor *keyword_editor;
      Fl_Input *filter_file_field;
      Fl_Button *filter_file_button;
      Fl_Text_Buffer *textbuf;

      Fineline_File_Map file_map;

      void start_filter_thread();
};

#endif // FINELINE_TREE_FILTER_DIALOG_H
