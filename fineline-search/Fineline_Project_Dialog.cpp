
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
   Fineline_File_Project_Dialog.cpp

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine FLTK GUI project dialog class implementation.

   Notes: EXPERIMENTAL

*/


#include "Fineline_Project_Dialog.h"

Fineline_Project_Dialog::Fineline_Project_Dialog(int x, int y, int w, int h) : Fl_Double_Window(x, y, w, h, "Fineline Project Dialog")
{
   //ctor
   begin();

   Fl_Group* dialog_group = new Fl_Group(5, 5, w - 5, h - 5);
   dialog_group->tooltip("Click the save button to save the case/project properties.");


   {
	   Fl_Button* o = new Fl_Button(w - 230, h - 45, 100, 30, "Save");
      o->callback((Fl_Callback*)button_callback, (void *)this);
      o->tooltip("Add the events to the timeline graph.");
   } // Fl_Button* o
   {
      Fl_Button* o = new Fl_Button(w - 120, h - 45, 100, 30, "Close");
      o->callback((Fl_Callback*)button_callback, (void *)this);
      o->tooltip("Close dialog without saving.");
   } // Fl_Button* o

   dialog_group->end();
   Fl_Group::current()->resizable(dialog_group);

   end();


}

Fineline_Project_Dialog::~Fineline_Project_Dialog()
{
   //dtor
}

void Fineline_Project_Dialog::button_callback(Fl_Button *b, void *p)
{
   //TODO: get the calling button label and execute the required action

   ((Fineline_Project_Dialog *)p)->hide();
}
