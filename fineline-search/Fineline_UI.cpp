
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

#include <iostream>

#include <FL/Fl_Box.H>
#include <FL/Fl_Tabs.H>
#include <FL/Fl_Group.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Button.H>
#include <FL/fl_ask.H>

#include "Fineline_UI.h"

using namespace std;

static Fineline_Thread *socket_thread;
static Fl_Browser *event_browser;
static Fineline_Log *flog;


Fineline_UI::Fineline_UI()
{
   Fl::scheme("plastic");
   window = new Fl_Double_Window(25, 35, Fl::w()-50, Fl::h()-50, "FineLine Forensic Image Analyser");

   menu = new Fl_Menu_Bar(0,0,800,30);		// Create menubar, items..
   menu->add("&File/&Open",    "^o", open_menu_callback);
   menu->add("&File/&Save",    "^s", save_menu_callback);
   menu->add("&File/&Save As", "^a", save_menu_callback);
   menu->add("&File/&Export",  "^e", export_menu_callback, 0, FL_MENU_DIVIDER);
   menu->add("&File/&Quit",    "^q", main_menu_callback);

   menu->add("&Edit/&Copy",    "^c", main_menu_callback);
   menu->add("&Edit/&Paste",   "^v", main_menu_callback, 0, FL_MENU_DIVIDER);
   menu->add("&Edit/Radio 1",   0, main_menu_callback, 0, FL_MENU_RADIO);
   menu->add("&Edit/Radio 2",   0, main_menu_callback, 0, FL_MENU_RADIO|FL_MENU_DIVIDER);
   menu->add("&Edit/Toggle 1",  0, main_menu_callback, 0, FL_MENU_TOGGLE);			// Default: off
   menu->add("&Edit/Toggle 2",  0, main_menu_callback, 0, FL_MENU_TOGGLE);			// Default: off
   menu->add("&Edit/Toggle 3",  0, main_menu_callback, 0, FL_MENU_TOGGLE|FL_MENU_VALUE);	// Default: on

   menu->add("&Help/Google",    0, main_menu_callback);
   menu->add("&Help/About",     0, main_menu_callback);

   menu->add("&Sockets/Start",  0, main_menu_callback);
   menu->add("&Sockets/Stop",   0, main_menu_callback);
   menu->add("&ACE/ACE Start",  0, main_menu_callback);
   menu->add("&ACE/ACE Stop",   0, main_menu_callback);

   // Define the top level Tabbed panel
      
   Fl_Tabs* tab_panel = new Fl_Tabs(10, 35, 800, 600);
   tab_panel->tooltip("the various index cards test different aspects of the Fl_Tabs widget");
   tab_panel->selection_color((Fl_Color)4);
   tab_panel->labelcolor(FL_BACKGROUND2_COLOR);
   
   // Tab 1 - the file browser tree and file content display tab
   cout << "Making tab 1...\n" << endl;

   Fl_Group* image_browser_tab = new Fl_Group(10, 60, 800, 600, "Volume&Browser");
   image_browser_tab->tooltip("Loads a file system from a forensice image into a tree browser");
         //o->selection_color((Fl_Color)1);
         //{
         //   Fl_Input* o = new Fl_Input(60, 80, 240, 40, "input:");
         //   o->tooltip("This is the first input field");
         //} // Fl_Input* o
         //{
            //box = new Fl_Box(20,40,760,100,"FineLine Search");
            //box->box(FL_UP_BOX);
            //box->labelfont(FL_BOLD+FL_ITALIC);
            //box->labelsize(36);
            //box->labeltype(FL_SHADOW_LABEL);
         //}
         //{
   event_browser = new Fl_Browser(20, 140, 760, 400);

   image_browser_tab->end();
   Fl_Group::current()->resizable(image_browser_tab);
   
   // Tab 2 - Event summary graph panel
   cout << "Making tab 2...\n" << endl;
   Fl_Group* summary_graph_tab = new Fl_Group(10, 60, 800, 600, "Summary Graph");
   summary_graph_tab->tooltip("TODO");
         //o->selection_color((Fl_Color)2);
   summary_graph_tab->hide();
         { 
			Fl_Button* o = new Fl_Button(20, 90, 100, 30, "button1");
            o->callback((Fl_Callback*)button_callback);
         }  // Fl_Button* o
         {
            Fl_Button* o = new Fl_Button(30, 200, 260, 30, "Test event blocking by modal window");
            o->callback((Fl_Callback*)button_callback);
         } // Fl_Button* o
   summary_graph_tab->end();
   Fl_Group::current()->resizable(summary_graph_tab);

   // Tab 3 - Timeline graph panel
   cout << "Making tab 3...\n" << endl;
   Fl_Group* timeline_graph_tab = new Fl_Group(10, 60, 800, 600, "Timeline Graph");
   timeline_graph_tab->tooltip("TODO");
         //o->selection_color((Fl_Color)3);
   timeline_graph_tab->hide();
         {
            new Fl_Button(20, 90, 60, 80, "button2");
         } // Fl_Button* o
         {
            new Fl_Button(80, 90, 60, 80, "button");
         } // Fl_Button* o
         {
            new Fl_Button(140, 90, 60, 80, "button");
         } // Fl_Button* o
   timeline_graph_tab->end();
   Fl_Group::current()->resizable(timeline_graph_tab);
         
   // Tab 4 - Text/Keyword search panel
   cout << "Making tab 4...\n" << endl;
   Fl_Group* search_tab = new Fl_Group(10, 60, 800, 6000, "&tab4");
   search_tab->tooltip("TODO");
         //o->selection_color((Fl_Color)5);
   search_tab->labeltype(FL_ENGRAVED_LABEL);
   search_tab->labelfont(2);
   search_tab->hide();
      {
            new Fl_Button(20, 80, 60, 110, "button2");
      } // Fl_Button* o
      {
            new Fl_Button(80, 80, 60, 110, "button");
      } // Fl_Button* o
      {
            new Fl_Button(140, 80, 60, 110, "button");
      } // Fl_Button* o
   search_tab->end();
   Fl_Group::current()->resizable(search_tab);

   tab_panel->end();
   Fl_Group::current()->resizable(tab_panel);

   window->end();
   //Fl_Group::current()->resizable(window); ??????????????????????

   flog = new Fineline_Log();
   flog->open_log_file();

   socket_thread = new Fineline_Thread(flog);

   cout << "Finished making UI...\n" << endl;
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
  fprintf(stderr, ", item_pathname() is '%s'\n", ipath);		   // ..and full pathname

  if (item->flags & (FL_MENU_RADIO|FL_MENU_TOGGLE))
  {		// Toggle or radio item?
    fprintf(stderr, ", value is %s", item->value()?"on":"off");	// Print item's value
  }
  else if ( strcmp(item->label(), "Google") == 0 )
  {
     fl_open_uri("http://google.com/");
  }
  else if ( strcmp(item->label(), "Start") == 0 )
  {
     socket_thread->start_task(event_browser);
  }
  else if ( strcmp(item->label(), "Stop") == 0 )
  {
	 socket_thread->stop_task();
  }
  else if ( strcmp(item->label(), "&Quit") == 0 )
  {
     exit(0);
  }
}


void Fineline_UI::open_menu_callback(Fl_Widget *w, void *x)
{
  Fl_Menu_Bar *menu_bar = (Fl_Menu_Bar*)w;				// Get the menubar widget
  const Fl_Menu_Item *item = menu_bar->mvalue();		// Get the menu item that was picked
  char ipath[256];

  menu_bar->item_pathname(ipath, sizeof(ipath));	   // Get full pathname of picked item
  fprintf(stderr, "callback: You picked '%s'", item->label());	// Print item picked
  fprintf(stderr, ", item_pathname() is '%s'\n", ipath);

}


void Fineline_UI::save_menu_callback(Fl_Widget *w, void *x)
{
   Fl_Menu_Bar *menu_bar = (Fl_Menu_Bar*)w;				// Get the menubar widget
   const Fl_Menu_Item *item = menu_bar->mvalue();		// Get the menu item that was picked
   char ipath[256];

   menu_bar->item_pathname(ipath, sizeof(ipath));	   // Get full pathname of picked item
   if ( strcmp(item->label(), "&Save") == 0 )
   {
	  // open the save file dialogue
   }
   else if ( strcmp(item->label(), "&Save As") == 0 )
   {
      // open the save as file dialogue
   }
}

void Fineline_UI::export_menu_callback(Fl_Widget *w, void *x)
{
	// open the export file dialogue
}


void Fineline_UI::update_screeninfo(Fl_Widget *b, void *p) 
{
    Fl_Browser *browser = (Fl_Browser *)p;
    int x, y, w, h;
    char line[128];
    browser->clear();

    sprintf(line, "Main screen work area: %dx%d@%d,%d", Fl::w(), Fl::h(), Fl::x(), Fl::y());
    browser->add(line);
    Fl::screen_work_area(x, y, w, h);
    sprintf(line, "Mouse screen work area: %dx%d@%d,%d", w, h, x, y);
    browser->add(line);

    for (int n = 0; n < Fl::screen_count(); n++) 
	{
	   int x, y, w, h;
	   Fl::screen_xywh(x, y, w, h, n);
	   sprintf(line, "Screen %d: %dx%d@%d,%d", n, w, h, x, y);
	   browser->add(line);
	   Fl::screen_work_area(x, y, w, h, n);
	   sprintf(line, "Work area %d: %dx%d@%d,%d", n, w, h, x, y);
	   browser->add(line);
    }
}

void Fineline_UI::button_callback(Fl_Button *b, void *p)
{
   fl_message("Make sure you cannot change the tabs while this modal window is up");
}
