

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
   Fineline_Export_Dialog.cpp

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 11/05/2014

   Purpose: FineLine FLTK GUI file export dialog. Provides functions to
            export files from a forensic image to an evidence folder.

   Notes: EXPERIMENTAL

*/



#include "Fineline_Export_Dialog.h"


Fl_Browser *Fineline_Export_Dialog::file_browser;

Fineline_Export_Dialog::Fineline_Export_Dialog(int x, int y, int w, int h) : Fl_Double_Window(x, y, w, h, "Fineline Export Dialog")
{
   begin();

   Fl_Group* browser_group = new Fl_Group(10, 10, w - 10, h - 10);
   {
      file_browser = new Fl_Browser(20, 20, w - 40, h - 100);
      Fl_Button* clear_button = new Fl_Button(w - 250, h - 50, 100, 30, "Export");
      clear_button->callback((Fl_Callback*)button_callback, (void *)this);
      Fl_Button* close_button = new Fl_Button(w - 140, h - 50, 100, 30, "Close");
      close_button->callback((Fl_Callback*)button_callback, (void *)this);
   }
   browser_group->end();
   Fl_Group::current()->resizable(browser_group);

   end();
}

Fineline_Export_Dialog::~Fineline_Export_Dialog()
{
   //dtor
}


void Fineline_Export_Dialog::button_callback(Fl_Button *b, void *p)
{
   ((Fineline_Export_Dialog *)p)->hide();
   return;
}
