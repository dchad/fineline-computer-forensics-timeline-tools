

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
   Fineline_File_Display_Dialog.h

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine FLTK GUI non-modal dialogue for display file contents.

   Notes: EXPERIMENTAL

*/


#ifndef FINELINE_FILE_DISPLAY_DIALOG_H
#define FINELINE_FILE_DISPLAY_DIALOG_H

#include <FL/Fl.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Browser.H>
#include <FL/Fl_Box.H>
#include <FL/filename.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Native_File_Chooser.H>

#include "fineline-search.h"


class Fineline_File_Display_Dialog : public Fl_Double_Window
{
   public:
      Fineline_File_Display_Dialog(int x, int y, int w, int h);
      virtual ~Fineline_File_Display_Dialog();

      static void button_callback(Fl_Button *b, void *p);

   protected:
   private:


      Fl_Browser *progress_browser;
};

#endif // FINELINE_FILE_DISPLAY_DIALOG_H
