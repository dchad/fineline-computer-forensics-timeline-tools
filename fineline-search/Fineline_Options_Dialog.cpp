


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
   Fineline_File_Options_Dialog.cpp

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine FLTK GUI options dialog class implementation.

   Notes: EXPERIMENTAL

*/


#include "Fineline_Options_Dialog.h"

Fineline_Options_Dialog::Fineline_Options_Dialog(int x, int y, int w, int h) : Fl_Double_Window(x, y, w, h, "Fineline Options")
{
   //ctor
   begin();

   {
	   Fl_Button* o = new Fl_Button(w - 230, h - 45, 100, 30, "Save As");
      o->callback((Fl_Callback*)button_callback, (void *)this);
      o->tooltip("Save to a text file.");
   } // Fl_Button* o
   {
      Fl_Button* o = new Fl_Button(w - 120, h - 45, 100, 30, "Close");
      o->callback((Fl_Callback*)button_callback, (void *)this);
      o->tooltip("Close dialog without saving.");
   } // Fl_Button* o

   end();
}

Fineline_Options_Dialog::~Fineline_Options_Dialog()
{
   //dtor
}

void Fineline_Options_Dialog::button_callback(Fl_Button *b, void *p)
{
   ((Fineline_Options_Dialog *)p)->hide();
}


int Fineline_Options_Dialog::open_options_file()
{
   return(0);
}

int Fineline_Options_Dialog::save_options_file()
{
   return(0);
}

int Fineline_Options_Dialog::close_options_file()
{
   return(0);
}

int Fineline_Options_Dialog::show_dialog()
{
   return(0);
}



