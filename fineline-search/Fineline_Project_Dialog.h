


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
   Fineline_File_Project_Dialog.h

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine FLTK GUI project dialog class definition.

   Notes: EXPERIMENTAL

*/

#ifndef FINELINE_PROJECT_DIALOG_H
#define FINELINE_PROJECT_DIALOG_H

#include <stdio.h>
#include <stdlib.h>
#include <string>

#include <FL/Fl.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Text_Editor.H>
#include <FL/Fl_Button.H>

#include "fineline-search.h"
#include "Fineline_Project.h"

class Fineline_Project_Dialog : public Fl_Double_Window
{
   public:
      Fineline_Project_Dialog(int x, int y, int w, int h, Fineline_Project *proj);
      virtual ~Fineline_Project_Dialog();

      void show_dialog(bool new_project);
      void clear_fields();

   protected:
   private:

   Fineline_Project *project_file;

   static void button_callback(Fl_Button *b, void *p);

   Fl_Input *project_name_field;
   Fl_Input *project_investigator_field;
   Fl_Input *project_summary_field;
   Fl_Input *project_start_date_field;
   Fl_Input *project_end_date_field;
   Fl_Text_Editor *project_description_field;

   Fl_Text_Buffer *textbuf;

};

#endif // FINELINE_PROJECT_DIALOG_H
