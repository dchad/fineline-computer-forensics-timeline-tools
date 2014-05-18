
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
Fineline_File_Metadata_Dialog *Fineline_UI::file_metadata_dialog;
Fineline_Progress_Dialog *Fineline_UI::progress_dialog;
Fineline_Export_Dialog *Fineline_UI::export_dialog;

Fineline_UI::Fineline_UI()
{

   int win_width = Fl::w() - 60;
   int win_height = Fl::h() - 80;
   Fl::scheme("plastic");
   window = new Fl_Double_Window(30, 30, win_width, win_height, "FineLine Forensic Image Analyser");

   //----------------------------------------------------------------------------------
   //   Create Main Menu
   //----------------------------------------------------------------------------------

   menu = new Fl_Menu_Bar(5,0, win_width - 10, 30);		// Create menubar, items..
   menu->add("&File/&New",     "^n", main_menu_callback);
   menu->add("&File/&Open",    "^o", open_menu_callback);
   menu->add("&File/&Save",    "^s", save_menu_callback);
   menu->add("&File/&Save As", "^a", save_menu_callback);
   menu->add("&File/&Export",  "^e", export_menu_callback, 0, FL_MENU_DIVIDER);
   menu->add("&File/&Quit",    "^q", main_menu_callback);

   menu->add("&Edit/&Copy",    "^c", main_menu_callback);
   menu->add("&Edit/&Paste",   "^v", main_menu_callback, 0, FL_MENU_DIVIDER);

   menu->add("&Help/Google",    0, main_menu_callback);
   menu->add("&Help/About",     0, main_menu_callback);

   //menu->add("&Sockets/Start",  0, main_menu_callback);
   //menu->add("&Sockets/Stop",   0, main_menu_callback);
   //menu->add("&ACE/ACE Start",  0, main_menu_callback);
   //menu->add("&ACE/ACE Stop",   0, main_menu_callback);

   //----------------------------------------------------------------------------------
   // Define the top level Tabbed panel
   //----------------------------------------------------------------------------------

   Fl_Tabs* tab_panel = new Fl_Tabs(5, 35, win_width - 10, win_height - 40);
   tab_panel->tooltip("Forensic image browser, timeline graphs and keyword searches.");
   tab_panel->selection_color((Fl_Color)4);
   tab_panel->labelcolor(FL_BACKGROUND2_COLOR);

   //----------------------------------------------------------------------------------
   // Tab 1 - the file browser tree and file content display tab
   //----------------------------------------------------------------------------------

   Fl_Group* image_browser_tab = new Fl_Group(5, 70, win_width - 10, win_height - 75, "Image Browser");
   image_browser_tab->tooltip("Displays a file system from a forensice image in a tree browser.");

   file_system_tree = new Fineline_File_System_Tree(10, 90, win_width/2 - 15, win_height - 145);
   file_system_tree->callback((Fl_Callback*)file_system_tree_callback, (void *)1234);

	save_tree_button = new Fl_Button(15, win_height - 45, 100, 30, "Save");
   save_tree_button->callback((Fl_Callback*)tree_button_callback);
   save_tree_button->tooltip("Save file tree to a text file.");
   filter_tree_button = new Fl_Button(125, win_height - 45, 100, 30, "Filter");
   filter_tree_button->callback((Fl_Callback*)tree_button_callback);
   filter_tree_button->tooltip("Open the file tree filter dialogue.");

   file_metadata_browser = new Fl_Browser(win_width/2 + 5, 90, win_width/2 - 15, win_height - 145);

	save_metadata_button = new Fl_Button(win_width/2 + 15, win_height - 45, 100, 30, "Save");
   save_metadata_button->callback((Fl_Callback*)file_metadata_callback);
   save_metadata_button->tooltip("Save metadata to a text file.");
   edit_metadata_button = new Fl_Button(win_width/2 + 125, win_height - 45, 100, 30, "Edit");
   edit_metadata_button->callback((Fl_Callback*)file_metadata_callback);
   edit_metadata_button->tooltip("Edit the metadata list.");
   timeline_metadata_button = new Fl_Button(win_width/2 + 235, win_height - 45, 100, 30, "Timeline");
   timeline_metadata_button->callback((Fl_Callback*)file_metadata_callback);
   timeline_metadata_button->tooltip("Add the metadata to the timeline graph.");
   clear_metadata_button = new Fl_Button(win_width/2 + 345, win_height - 45, 100, 30, "Clear");
   clear_metadata_button->callback((Fl_Callback*)file_metadata_callback);
   clear_metadata_button->tooltip("Clear the metadata list.");

   // File tree popup menu
   popup_menu = new Fl_Menu_Button(10, 90, win_width/2 - 15, win_height - 130);
   popup_menu->type(Fl_Menu_Button::POPUP3); // Right mouse button click.
   popup_menu->add("Mark File|Unmark File|Open File|Export Files|Copy Metadata|Timeline");
   popup_menu->callback(popup_menu_callback);

   image_browser_tab->end();
   Fl_Group::current()->resizable(image_browser_tab);

   //----------------------------------------------------------------------------------
   // Tab 2 - Event summary graph panel
   //----------------------------------------------------------------------------------

   Fl_Group* statistical_graph_tab = new Fl_Group(5, 70, win_width - 10, win_height - 75, "Statistics Graph");
   statistical_graph_tab->tooltip("Summary graph of file system activity.");
   statistical_graph_tab->hide();
   {
	   Fl_Button* o = new Fl_Button(20, 90, 100, 30, "button1");
      o->callback((Fl_Callback*)button_callback);
   }  // Fl_Button* o
   {
      Fl_Button* o = new Fl_Button(20, 200, 100, 30, "modal window");
      o->callback((Fl_Callback*)button_callback);
   } // Fl_Button* o
   statistical_graph_tab->end();
   Fl_Group::current()->resizable(statistical_graph_tab);

   //----------------------------------------------------------------------------------
   // Tab 3 - Timeline graph panel
   //----------------------------------------------------------------------------------

   Fl_Group* timeline_graph_tab = new Fl_Group(5, 70, win_width - 10, win_height - 75, "Timeline Graph");
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

   //----------------------------------------------------------------------------------
   // Tab 4 - Text/Keyword search panel
   //----------------------------------------------------------------------------------

   Fl_Group* search_tab = new Fl_Group(5, 70, win_width - 10, win_height - 75, "Keyword Search");
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

   //----------------------------------------------------------------------------------
   // Now make all the ancillary objects.
   //----------------------------------------------------------------------------------

   flog = new Fineline_Log();
   flog->open_log_file();
   fc = new Fl_Native_File_Chooser();
   socket_thread = new Fineline_Thread(flog);

   //----------------------------------------------------------------------------------
   // Now make the dialogs
   //----------------------------------------------------------------------------------

   event_dialog = new Fineline_Event_Dialog(win_width/2 - 300, win_height/2 - 300, 800, 600);
   file_metadata_dialog = new Fineline_File_Metadata_Dialog(win_width/2 - 300, win_height/2 - 300, 800, 600);
   progress_dialog = new Fineline_Progress_Dialog(win_width/2 - 300, win_height/2 - 300, 800, 600);
   export_dialog = new Fineline_Export_Dialog(win_width/2 - 300, win_height/2 - 300, 800, 600);

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

/*
   Name   : main_menu_callback()
   Purpose: Called from the main menu to perform various functions.
   Input  : FLTK menu bar widget.
   Output : None.
*/
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

/*
   Name   : open_menu_callback()
   Purpose: Called from the main menu to open project files
            or forensic images.
   Input  : FLTK menu button widget.
   Output : None.
*/
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
      default:		      // Choice
         fc->preset_file(fc->filename());
         //load_forensic_image(fc->filename()); DEPRECATED for large forensic images.
         start_image_process_thread(fc->filename());
   }

   return;
}

/*
   Name   : save_menu_callback()
   Purpose: Called from the main menu to save the current project
            or create a new project file.
   Input  : FLTK menu bar widget.
   Output : None.
*/
void Fineline_UI::save_menu_callback(Fl_Widget *w, void *x)
{
   Fl_Menu_Bar *menu_bar = (Fl_Menu_Bar*)w;				// Get the menubar widget
   const Fl_Menu_Item *item = menu_bar->mvalue();		// Get the menu item that was picked
   char ipath[256];

   menu_bar->item_pathname(ipath, sizeof(ipath));	   // Get full pathname of picked item
   if ( strncmp(item->label(), "&Save", 5) == 0 )
   {
	  // TODO: open the save file dialogue
   }
   else if ( strncmp(item->label(), "&Save As", 8) == 0 )
   {
      // TODO: open the save as file dialogue
   }
   return;
}

/*
   Name   : export_menu_callback()
   Purpose: Called from the main menu to open the export dialogue to
            export marked files from the forensic image.
   Input  : FLTK menu button widget.
   Output : None.
*/
void Fineline_UI::export_menu_callback(Fl_Widget *w, void *x)
{
   if (DEBUG)
      cout << "Fineline_UI::popup_menu_callback() <INFO> " << endl;
	// TODO: open the export file dialogue
	// need the hashmap of file records with marked files and
	// pointer to the file system object.

	export_dialog->add_marked_files(file_system_tree->get_marked_files(), file_system);
	export_dialog->show();

	return;
}

/*
   Name   : popup_menu_callback()
   Purpose: Called by right clicking on the file system tree widget
            to run various functions such as marking file nodes and
            exporting files from the forensic image.
   Input  : FLTK menu button widget.
   Output : None.
*/
void Fineline_UI::popup_menu_callback(Fl_Widget *w, void *x)
{
   Fl_Menu_Button *menu_button = (Fl_Menu_Button*)w;		// Get the menubar widget.
   const Fl_Menu_Item *item = menu_button->mvalue();		// Get the menu item that was picked.

   //TODO: add unmark all menu item.

   if ( strncmp(item->label(), "Mark File", 9) == 0 )
   {
      // mark the file/directory for later processing/reporting/exporting etc.
      file_system_tree->mark_file();
      if (DEBUG)
         cout << "Fineline_UI::popup_menu_callback() <INFO> " << item->label() << endl;
   }
   else if ( strncmp(item->label(), "Unmark File", 11) == 0 )
   {
      file_system_tree->unmark_file();
      if (DEBUG)
         cout << "Fineline_UI::popup_menu_callback() <INFO> " << item->label() << endl;
   }
   else if ( strncmp(item->label(), "Open File", 9) == 0 )
   {
      //TODO: display the file (images/video/text/docs/web pages) in a dialogue or for unknown binary files open a hex editor.
      if (DEBUG)
         cout << "Fineline_UI::popup_menu_callback() <INFO> " << item->label() << endl;
   }
   else if ( strncmp(item->label(), "Export Files", 12) == 0 )
   {
      export_dialog->add_marked_files(file_system_tree->get_marked_files(), file_system);
	   export_dialog->show();

      if (DEBUG)
         cout << "Fineline_UI::popup_menu_callback() <INFO> " << item->label() << endl;
   }
   else if ( strncmp(item->label(), "Copy Metadata", 13) == 0 )
   {
	  //TODO: copy the file metadata as text to the system clipboard.
      if (DEBUG)
         cout << "Fineline_UI::popup_menu_callback() <INFO> " << item->label() << endl;
   }
   else if ( strncmp(item->label(), "Timeline", 8) == 0 )
   {
      // open the event dialogue to create fineline event records for the marked files and add to the timeline graph.
      event_dialog->add_marked_files(file_system_tree->get_marked_files());
      event_dialog->show();
   }
   return;
}

/*
   Name   : file_system_tree_callback()
   Purpose: Called by a click on the tree widget nodes.
   Input  : Tree widget pointer.
   Output : None.
*/
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

#ifndef LINUX_BUILD
         if ((flrec->file_type == TSK_FS_META_TYPE_DIR) && (strncmp(flrec->file_name, "winsxs", 6) == 0))
         {
            file_system_tree->add_file_nodes(file_path);
         }
#endif

      }
      else
      {
         flog->print_log_entry("file_system_tree_callback() <ERROR> Could not get find file record.");
         fl_message(" <ERROR> Could not get find file record. ");
      }
   }

   return;
}

/*
   Name   : file_metadata_callback()
   Purpose: Called by clicks on the button widgets of the file metadata group.
   Input  : FLTK button widget.
   Output : None.
*/
void Fineline_UI::file_metadata_callback(Fl_Widget *w, void *x)
{
   Fl_Button *fb = (Fl_Button *)w;

   if ( strncmp(fb->label(), "Save", 4) == 0 )
   {
      // Open the file chooser dialog to select a file to save the metadata text.
      if (DEBUG)
         cout << "Fineline_UI::file_metadata_callback() <INFO> " << fb->label() << endl;

   }
   else if ( strncmp(fb->label(), "Edit", 4) == 0 )
   {
      int i;
      string metadata;
      // Edit the text in the metadata browser.
      if (DEBUG)
         cout << "Fineline_UI::file_metadata_callback() <INFO> " << fb->label() << endl;
      for (i = 1; i < file_metadata_browser->size()+1; i++)
      {
         metadata.append(file_metadata_browser->text(i));
         metadata.append("\n");
         file_metadata_dialog->add_metadata(metadata);
         metadata.clear();
      }

      file_metadata_dialog->show();
   }
   else if ( strncmp(fb->label(), "Export", 6) == 0 )
   {
      // TODO: open file chooser the text from the metadata browser.
      if (DEBUG)
         cout << "Fineline_UI::file_metadata_callback() <INFO> " << fb->label() << endl;

   }
   else if ( strncmp(fb->label(), "Clear", 5) == 0 )
   {
      // Clear the text from the metadata browser.
      if (DEBUG)
         cout << "Fineline_UI::file_metadata_callback() <INFO> " << fb->label() << endl;
      file_metadata_browser->clear();
      file_metadata_dialog->clear_metadata();
   }
   return;
}

void Fineline_UI::button_callback(Fl_Button *b, void *p)
{
   fl_message("modal window");
   return;
}

/*
   Name   : tree_button_callback()
   Purpose: Called by clicks on the button widgets of the file system tree group.
   Input  : FLTK button widget.
   Output : None.
*/
void Fineline_UI::tree_button_callback(Fl_Button *b, void *p)
{
   if ( strcmp(b->label(), "Save") == 0 )
   {

      if (DEBUG)
         cout << "Fineline_UI::tree_button_callback() <INFO> " << b->label() << endl;

      fc->title("Save File System Tree");
      fc->type(Fl_Native_File_Chooser::BROWSE_FILE);		// only picks files that exist
      switch ( fc->show() )
      {
         case -1: break;	// Error
         case  1: break; 	// Cancel
         default:		      // Choice
         fc->preset_file(fc->filename());
         save_tree(fc->filename());
      }
   }
   else if ( strcmp(b->label(), "Filter") == 0 )
   {
      if (DEBUG)
         cout << "Fineline_UI::tree_button_callback() <INFO> " << b->label() << endl;

      //TODO: open the filter dialog
   }
   return;
}

/*
   Name   : update_file_metadata_browser()
   Purpose: Adds the file metadata to the metadata browser widget.
   Input  : Pointer to the file metadata record.
   Output : None.
*/
void Fineline_UI::update_file_metadata_browser(fl_file_record_t *flrec)
{
   string metadata;

   file_metadata_browser->add("<metadata>");

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

   file_metadata_browser->add("</metadata>");

   file_metadata_browser->bottomline(file_metadata_browser->size());

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

   file_system_tree->clear_tree();

   if (file_system != NULL)
      delete file_system;

   file_system = new Fineline_File_System(file_system_tree, fns, progress_dialog, flog);

   if (file_system == NULL)
   {
      flog->print_log_entry("Fineline_UI::load_forensic_image() <ERROR> Could not create file system object.\n");
      return(-1);
   }
   progress_dialog->show();

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
   file_system = new Fineline_File_System(file_system_tree, fns, progress_dialog, flog);

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


/*
   Name   : save_tree()
   Purpose: Writes out the forensic image file system tree to a text file.
   Input  : filename.
   Output : returns 0 on success, -1 on fail.

*/
int Fineline_UI::save_tree(const char *filename)
{
   //TODO: open file and write out the file system tree.

   return(0);
}



// Unit testing only.
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
