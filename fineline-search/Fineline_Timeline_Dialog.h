

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
   Fineline_Timeline_Dialog.h

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine FLTK GUI dialog to add events to the timeline graph.

   Notes: EXPERIMENTAL

*/


#ifndef FINELINE_TIMELINE_DIALOG_H
#define FINELINE_TIMELINE_DIALOG_H

#include <vector>
#include <string>

#include <FL/Fl.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Browser.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Button.H>

#include "fineline-search.h"
#include "Fineline_File_Metadata_Browser.h"

using namespace std;

class Fineline_Timeline_Dialog : public Fl_Double_Window
{

   public:

      Fineline_Timeline_Dialog(int x, int y, int w, int h);
      virtual ~Fineline_Timeline_Dialog();

      void add_marked_files(vector< fl_file_record_t* > flist);

   protected:
   private:

      Fineline_File_Metadata_Browser *file_browser;

      static void button_callback(Fl_Button *b, void *p);
};

#endif // FINELINE_TIMELINE_DIALOG_H
