
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
   Fineline_Export_Dialog.h

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 11/05/2014

   Purpose: FineLine FLTK GUI file export dialog. Provides functions to
            export files from a forensic image to an evidence folder.

   Notes: EXPERIMENTAL

*/




#ifndef FINELINE_EXPORT_DIALOG_H
#define FINELINE_EXPORT_DIALOG_H

#include <vector>

#include <FL/Fl.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Browser.H>
#include <FL/Fl_Button.H>

#include "fineline-search.h"

using namespace std;

class Fineline_Export_Dialog : public Fl_Double_Window
{
   public:
      Fineline_Export_Dialog(int x, int y, int w, int h);
      virtual ~Fineline_Export_Dialog();

      void add_marked_files(vector< fl_file_record_t* > flist);

   protected:
   private:

      vector< fl_file_record_t* > marked_file_list;

      static Fl_Browser *file_browser;

      static void button_callback(Fl_Button *b, void *p);
};

#endif // FINELINE_EXPORT_DIALOG_H
