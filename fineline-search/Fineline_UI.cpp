
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
   Fineline_UI.cpp

   Title : FineLine Computer Forensics Image Searcher GUI
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine FLTK GUI.

   Notes: EXPERIMENTAL

*/

#include "Fineline_UI.h"

static Fineline_Thread *socket_thread;
static Fl_Browser *event_browser;
static Fineline_Log *flog;

Fineline_UI::Fineline_UI()
{
   window = new Fl_Double_Window(800,600);

   menu = new Fl_Menu_Bar(0,0,800,30);		// Create menubar, items..
   menu->add("&File/&Open",  "^o", main_menu_callback);
   menu->add("&File/&Save",  "^s", main_menu_callback, 0, FL_MENU_DIVIDER);
   menu->add("&File/&Quit",  "^q", main_menu_callback);
   menu->add("&Edit/&Copy",  "^c", main_menu_callback);
   menu->add("&Edit/&Paste", "^v", main_menu_callback, 0, FL_MENU_DIVIDER);
   menu->add("&Edit/Radio 1",   0, main_menu_callback, 0, FL_MENU_RADIO);
   menu->add("&Edit/Radio 2",   0, main_menu_callback, 0, FL_MENU_RADIO|FL_MENU_DIVIDER);
   menu->add("&Edit/Toggle 1",  0, main_menu_callback, 0, FL_MENU_TOGGLE);			// Default: off
   menu->add("&Edit/Toggle 2",  0, main_menu_callback, 0, FL_MENU_TOGGLE);			// Default: off
   menu->add("&Edit/Toggle 3",  0, main_menu_callback, 0, FL_MENU_TOGGLE|FL_MENU_VALUE);	// Default: on
   menu->add("&Help/Google",    0, main_menu_callback);

   menu->add("&Sockets/Start",  0, main_menu_callback);
   menu->add("&Sockets/Stop",   0, main_menu_callback);
   menu->add("&ACE/ACE Start",  0, main_menu_callback);
   menu->add("&ACE/ACE Stop",   0, main_menu_callback);


   box = new Fl_Box(20,40,760,100,"FineLine Search");
   box->box(FL_UP_BOX);
   box->labelfont(FL_BOLD+FL_ITALIC);
   box->labelsize(36);
   box->labeltype(FL_SHADOW_LABEL);

   event_browser = new Fl_Browser(20, 140, 760, 400);

   window->end();

   flog = new Fineline_Log();
   socket_thread = new Fineline_Thread(flog);

}

Fineline_UI::~Fineline_UI()
{
   //dtor
}


void Fineline_UI::show(int argc, char *argv[])
{
   window->show(argc, argv);
}

void Fineline_UI::main_menu_callback(Fl_Widget *w, void *x)
{
  Fl_Menu_Bar *menu_bar = (Fl_Menu_Bar*)w;				// Get the menubar widget
  const Fl_Menu_Item *item = menu_bar->mvalue();		// Get the menu item that was picked
  char ipath[256];

  menu_bar->item_pathname(ipath, sizeof(ipath));	   // Get full pathname of picked item

  fprintf(stderr, "callback: You picked '%s'", item->label());	// Print item picked
  fprintf(stderr, ", item_pathname() is '%s'", ipath);		   // ..and full pathname

  if (item->flags & (FL_MENU_RADIO|FL_MENU_TOGGLE))
  {		// Toggle or radio item?
    fprintf(stderr, ", value is %s", item->value()?"on":"off");	// Print item's value
  }
  fprintf(stderr, "\n");
  if ( strcmp(item->label(), "Google") == 0 )
  {
     fl_open_uri("http://google.com/");
  }
  if ( strcmp(item->label(), "Start") == 0 )
  {
     socket_thread->start_task(event_browser);
  }
  if ( strcmp(item->label(), "Stop") == 0 )
  {
	 socket_thread->stop_task();
  }
  if ( strcmp(item->label(), "&Quit") == 0 )
  {
     exit(0);
  }
}
