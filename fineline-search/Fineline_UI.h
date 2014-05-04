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
   Fineline_UI.h

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine FLTK GUI.

   Notes: EXPERIMENTAL

*/


#ifndef FINELINE_UI_H
#define FINELINE_UI_H

#include <FL/Fl.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Browser.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Menu_Bar.H>
#include <FL/filename.H>

#include "Fineline_Thread_FLTK.h"

class Fineline_UI
{
   public:
      Fineline_UI();
      ~Fineline_UI();

      void show(int argc, char *argv[]);
      //Fl_Browser *get_browser();
	  static void main_menu_callback(Fl_Widget *w, void *x);
	  static void open_menu_callback(Fl_Widget *w, void *x);
	  static void save_menu_callback(Fl_Widget *w, void *x);
	  static void export_menu_callback(Fl_Widget *w, void *x);

   protected:
   private:

      Fl_Double_Window *window;
      Fl_Menu_Bar *menu;
      Fl_Box *box;

};

#endif // FINELINE_UI_H
