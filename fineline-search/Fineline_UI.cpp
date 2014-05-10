
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

   Purpose: FineLine FLTK GUI. Consists of a main window widget containing:
            Tabbed Panel
               |-> Tab 1 : File System Tree and file metadata browser.
               |-> Tab 2 : Statistical graph of the file system.
               |-> Tab 3 : Timeline graph.
               |-> Tab 4 : Keyword search panel.

   Notes: EXPERIMENTAL

*/

#include <iostream>

#include <FL/Fl_Box.H>
#include <FL/Fl_Tabs.H>
#include <FL/Fl_Tree.H>
#include <FL/Fl_Group.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Button.H>
#include <FL/fl_ask.H>

#include "Fineline_UI.h"


using namespace std;

Fineline_Thread *Fineline_UI::socket_thread;
Fl_Browser *Fineline_UI::file_metadata_browser;
Fineline_File_System_Tree *Fineline_UI::file_system_tree;
Fineline_File_System *Fineline_UI::file_system;
Fl_Native_File_Chooser *Fineline_UI::fc;
Fineline_Log *Fineline_UI::flog;
Fineline_Event_Dialog *Fineline_UI::event_dialog;

Fineline_UI::Fineline_UI()
{

   int win_width = Fl::w() - 60;
   int win_height = Fl::h() - 80;
   Fl::scheme("plastic");
   window = new Fl_Double_Window(30, 30, win_width, win_height, "FineLine Forensic Image Analyser");

   menu = new Fl_Menu_Bar(5,0, win_width - 10, 30);		// Create menubar, items..
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

   Fl_Tabs* tab_panel = new Fl_Tabs(5, 35, win_width - 10, win_height - 70);
   tab_panel->tooltip("Forensic image browser, timeline graphs and keyword searches.");
   tab_panel->selection_color((Fl_Color)4);
   tab_panel->labelcolor(FL_BACKGROUND2_COLOR);

   // Tab 1 - the file browser tree and file content display tab

   Fl_Group* image_browser_tab = new Fl_Group(5, 70, win_width - 10, win_height - 80, "Image Browser");
   image_browser_tab->tooltip("Displays a file system from a forensice image in a tree browser.");

   file_system_tree = new Fineline_File_System_Tree(10, 90, win_width/2 - 15, win_height - 200);
   file_system_tree->callback((Fl_Callback*)file_system_tree_callback, (void *)1234);

   file_metadata_browser = new Fl_Browser(win_width/2 + 5, 90, win_width/2 - 15, win_height - 200);
   file_metadata_browser->callback(file_metadata_callback);

   popup_menu = new Fl_Menu_Button(10, 90, win_width/2 - 15, win_height - 200);
   popup_menu->type(Fl_Menu_Button::POPUP3); // Right mouse button click.
   popup_menu->add("Mark File|Open File|Export File|Copy Metadata|Create Event");
   popup_menu->callback(popup_menu_callback);

   image_browser_tab->end();
   Fl_Group::current()->resizable(image_browser_tab);

   // Tab 2 - Event summary graph panel

   Fl_Group* statistical_graph_tab = new Fl_Group(5, 70, win_width - 10, win_height - 80, "Statistics Graph");
   statistical_graph_tab->tooltip("Summary graph of file system activity.");
         //o->selection_color((Fl_Color)2);
   statistical_graph_tab->hide();
         {
			Fl_Button* o = new Fl_Button(20, 90, 100, 30, "button1");
            o->callback((Fl_Callback*)button_callback);
         }  // Fl_Button* o
         {
            Fl_Button* o = new Fl_Button(30, 200, 260, 30, "Test event blocking by modal window");
            o->callback((Fl_Callback*)button_callback);
         } // Fl_Button* o
   statistical_graph_tab->end();
   Fl_Group::current()->resizable(statistical_graph_tab);

   // Tab 3 - Timeline graph panel

   Fl_Group* timeline_graph_tab = new Fl_Group(5, 70, win_width - 10, win_height - 80, "Timeline Graph");
   timeline_graph_tab->tooltip("File System Event Timeline");
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

   Fl_Group* search_tab = new Fl_Group(5, 70, win_width - 10, win_height - 80, "Keyword Search");
   search_tab->tooltip("File System Keyword Search");
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

   // Now make all the ancillary objects.

   flog = new Fineline_Log();
   flog->open_log_file();
   fc = new Fl_Native_File_Chooser();
   socket_thread = new Fineline_Thread(flog);

   // Now make the dialogs

   event_dialog = new Fineline_Event_Dialog(win_width/2 - 200, win_height/2 - 200, 400, 400);

   if (DEBUG)
      cout << "Fineline_UI.ctor() <INFO> Finished making UI...\n" << endl;
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
     socket_thread->start_task(file_metadata_browser);
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

   fc->title("Open");
   fc->type(Fl_Native_File_Chooser::BROWSE_FILE);		// only picks files that exist
   switch ( fc->show() )
   {
      case -1: break;	// Error
      case  1: break; 	// Cancel
      default:		    // Choice
         fc->preset_file(fc->filename());
         //load_forensic_image(fc->filename()); DEPRECATED for large forensic images.
         start_image_process_thread(fc->filename());
   }

   return;
}


void Fineline_UI::save_menu_callback(Fl_Widget *w, void *x)
{
   Fl_Menu_Bar *menu_bar = (Fl_Menu_Bar*)w;				// Get the menubar widget
   const Fl_Menu_Item *item = menu_bar->mvalue();		// Get the menu item that was picked
   char ipath[256];

   menu_bar->item_pathname(ipath, sizeof(ipath));	   // Get full pathname of picked item
   if ( strcmp(item->label(), "&Save") == 0 )
   {
	  // TODO: open the save file dialogue
   }
   else if ( strcmp(item->label(), "&Save As") == 0 )
   {
      // TODO: open the save as file dialogue
   }
   return;
}

void Fineline_UI::export_menu_callback(Fl_Widget *w, void *x)
{
   if (DEBUG)
      cout << "Fineline_UI::popup_menu_callback() <INFO> " << endl;
	// TODO: open the export file dialogue
	return;
}

void Fineline_UI::popup_menu_callback(Fl_Widget *w, void *x)
{
   Fl_Menu_Button *menu_button = (Fl_Menu_Button*)w;		// Get the menubar widget.
   const Fl_Menu_Item *item = menu_button->mvalue();		// Get the menu item that was picked.

   if ( strcmp(item->label(), "Mark File") == 0 )
   {
      // mark the file/directory for later processing/reporting/exporting etc.
      if (DEBUG)
         cout << "Fineline_UI::popup_menu_callback() <INFO> " << item->label() << endl;
   }
   else if ( strcmp(item->label(), "Open File") == 0 )
   {
      // display the file (images/video/text/docs/web pages) in a dialogue or for unknown binary files open a hex editor.
      if (DEBUG)
         cout << "Fineline_UI::popup_menu_callback() <INFO> " << item->label() << endl;
   }
   else if ( strcmp(item->label(), "Export File") == 0 )
   {
      // copy the selected file/directory from the forensic image to an evidence folder.
      if (DEBUG)
         cout << "Fineline_UI::popup_menu_callback() <INFO> " << item->label() << endl;
   }
   else if ( strcmp(item->label(), "Copy Metadata") == 0 )
   {
	  // copy the file metadata as text to the system clipboard.
      if (DEBUG)
         cout << "Fineline_UI::popup_menu_callback() <INFO> " << item->label() << endl;
   }
   else if ( strcmp(item->label(), "Create Event") == 0 )
   {
      // open the event dialogue to create a fineline event record and add to the timeline.
      //if (DEBUG)
      //   cout << "Fineline_UI::popup_menu_callback() <INFO> " << item->label() << endl;

      event_dialog->show();
   }
   return;
}

void Fineline_UI::file_system_tree_callback(Fl_Tree *flt, void *x)
{
	//DEPRECATED: Fl_Tree_Item * flti = flt->item_clicked();
	Fl_Tree_Item *flti = file_system_tree->callback_item();
   fl_file_record_t *flrec = NULL;
   char file_path[FL_PATH_MAX]; // FL_PATH_MAX 2048 is an FLTK constant, Fineline FL_PATH_MAX_LENGTH 4096

   if (file_system_tree->item_pathname(file_path, FL_PATH_MAX, flti) != 0)
   {
      flog->print_log_entry("file_system_tree_callback() <ERROR> Could not get tree item path.");
      fl_message(" <ERROR> Could not get tree item. ");
      return;
   }

   if (flt->callback_reason() == FL_TREE_REASON_SELECTED)
   {
      flrec = file_system_tree->find_file(file_path);
      if (flrec != NULL)
      {
         update_file_metadata_browser(flrec);
      }
      else
      {
         flog->print_log_entry("file_system_tree_callback() <ERROR> Could not get find file record.");
         fl_message(" <ERROR> Could not get find file record. ");
      }
   }

   return;
}

void Fineline_UI::file_metadata_callback(Fl_Widget *w, void *x)
{
   //Fl_Browser *fb = (Fl_Browser *)w;
   if (DEBUG)
      cout << "Fineline_UI::file_metadata_callback() <INFO> " << endl;

   return;
}

void Fineline_UI::button_callback(Fl_Button *b, void *p)
{
   fl_message("Make sure you cannot change the tabs while this modal window is up");
   return;
}


void Fineline_UI::update_file_metadata_browser(fl_file_record_t *flrec)
{
   string metadata;

   //file_metadata_browser->clear();
   metadata.append("Filename : ");
   metadata.append(flrec->file_name);
   file_metadata_browser->add(metadata.c_str());

   metadata.clear();
   metadata.append("Filepath : ");
   metadata.append(flrec->file_path);
   file_metadata_browser->add(metadata.c_str());

   metadata.clear();
   metadata.append("Creation Time : ");
   file_metadata_browser->add(metadata.c_str());

   metadata.clear();
   metadata.append("Access Time : ");
   file_metadata_browser->add(metadata.c_str());

   metadata.clear();
   metadata.append("File Size : ");
   file_metadata_browser->add(metadata.c_str());

   metadata.clear();
   metadata.append("File Owner : ");
   file_metadata_browser->add(metadata.c_str());

   metadata.clear();
   metadata.append("MD5 Hash : ");
   file_metadata_browser->add(metadata.c_str());

   return;
}

/*
   Name   : start_image_process_thread()
   Purpose: creates a file system object to process the image file system(s)
            in a thread. Recommended for large forensic images so the GUI
            does not block.
   Input  : file path of the forensic image.
   Output : returns 0 on success, -1 on fail.

*/
int Fineline_UI::start_image_process_thread(const char *filename)
{
   string fns = filename;
   file_system = new Fineline_File_System(file_system_tree, fns, flog);

   if (file_system == NULL)
   {
      flog->print_log_entry("Fineline_UI::load_forensic_image() <ERROR> Could not create file system object.\n");
      return(-1);
   }
   file_system->start_task(); //Note: do not delete file system object after starting the thread

   return(0);
}

/*
   Name   : load_forensic_image()
   Purpose: creates a file system object to process the image file system(s).
   Input  : file path of the forensic image.
   Output : returns 0 on success, -1 on fail.

*/
int Fineline_UI::load_forensic_image(const char *filename)
{
   string fns = filename;
   file_system = new Fineline_File_System(file_system_tree, fns, flog);

   if (file_system == NULL)
   {
      flog->print_log_entry("Fineline_UI::load_forensic_image() <ERROR> Could not create file system object.\n");
      return(-1);
   }
   if (file_system->open_forensic_image() == -1)
   {
      flog->print_log_entry("Fineline_UI::load_forensic_image() <ERROR> Could not open image file.\n");
      return(-1);
   }
   if (file_system->process_forensic_image() == -1)
   {
      flog->print_log_entry("Fineline_UI::load_forensic_image() <ERROR> Could process open image file.\n");
      return(-1);
   }
   file_system->close_forensic_image();

   delete file_system;

   return(0);
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
   return;
}
