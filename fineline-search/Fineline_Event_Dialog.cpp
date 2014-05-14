

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
   Fineline_Event_Dialog.cpp

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine FLTK GUI event editor dialog.

   Notes: EXPERIMENTAL

*/

#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Menu_Item.H>
#include <FL/Fl_Menu_Bar.H>

#include "Fineline_Event_Dialog.h"
#include "Fineline_Log.h"


Fl_Text_Buffer *text_buffer = 0;

#define TEXTSIZE 14

Fineline_Event_Dialog::Fineline_Event_Dialog(int x, int y, int w, int h) : Fl_Double_Window(x, y ,w, h, "Event Editor")
{
   begin();

   Fl_Menu_Item menuitems[] = {
   { "&File",              0, 0, 0, FL_SUBMENU },
    { "&Open File...",    FL_COMMAND + 'o', (Fl_Callback *)open_cb },
    { "&Insert File...",  FL_COMMAND + 'i', (Fl_Callback *)insert_cb, 0, FL_MENU_DIVIDER },
    { "&Save File",       FL_COMMAND + 's', (Fl_Callback *)save_cb },
    { "Save File &As...", FL_COMMAND + FL_SHIFT + 's', (Fl_Callback *)saveas_cb, 0, FL_MENU_DIVIDER },
    { "&Close View",      FL_COMMAND + 'w', (Fl_Callback *)close_cb, 0, FL_MENU_DIVIDER },
    { "E&xit",            FL_COMMAND + 'q', (Fl_Callback *)quit_cb, 0 },
    { 0 },

   { "&Edit", 0, 0, 0, FL_SUBMENU },
    { "Cu&t",             FL_COMMAND + 'x', (Fl_Callback *)cut_cb },
    { "&Copy",            FL_COMMAND + 'c', (Fl_Callback *)copy_cb },
    { "&Paste",           FL_COMMAND + 'v', (Fl_Callback *)paste_cb },
    { "&Delete",          0, (Fl_Callback *)delete_cb },
    { 0 },

   { "&Search", 0, 0, 0, FL_SUBMENU },
    { "&Find...",         FL_COMMAND + 'f', (Fl_Callback *)find_cb },
    { "F&ind Again",      FL_COMMAND + 'g', find_next_cb },
    { "&Replace...",      FL_COMMAND + 'r', replace_cb },
    { "Re&place Again",   FL_COMMAND + 't', replace_next_cb },
    { 0 },

    { 0 }
   };
   Fl_Menu_Bar* m = new Fl_Menu_Bar(5, 0, w - 5, 30);
   m->copy(menuitems, this);

   Fl_Group* event_group = new Fl_Group(5, 35, w - 5, h - 35);
   event_group->tooltip("Edit the file metadata items and click the save button to add the event to the timeline graph.");

   text_buffer = new Fl_Text_Buffer;
   teditor = new Fl_Text_Editor(10, 40, w - 10, h - 95);
   teditor->textfont(FL_COURIER);
   teditor->textsize(TEXTSIZE);
   teditor->buffer(text_buffer);
   text_buffer->text();
   {
	   Fl_Button* o = new Fl_Button(w - 340, h - 45, 100, 30, "Save");
      o->callback((Fl_Callback*)button_callback, (void *)this);
      o->tooltip("Save events to a text file.");
   } // Fl_Button* o
   {
	   Fl_Button* o = new Fl_Button(w - 230, h - 45, 100, 30, "Timeline");
      o->callback((Fl_Callback*)button_callback, (void *)this);
      o->tooltip("Add the events to the timeline graph.");
   } // Fl_Button* o
   {
      Fl_Button* o = new Fl_Button(w - 120, h - 45, 100, 30, "Close");
      o->callback((Fl_Callback*)button_callback, (void *)this);
      o->tooltip("Close dialog without saving.");
   } // Fl_Button* o
   event_group->end();
   Fl_Group::current()->resizable(event_group);

   end();

}

Fineline_Event_Dialog::~Fineline_Event_Dialog()
{
   //dtor
}


void Fineline_Event_Dialog::add_marked_files(vector< fl_file_record_t* > flist)
{
   unsigned int i;
   marked_file_list = flist;
   char full_path[FL_PATH_MAX];

   for (i = 0; i < marked_file_list.size(); i++)
   {
      memset((void*)full_path, 0, FL_PATH_MAX);
      fl_file_record_t *flec = marked_file_list[i];
      strncpy(full_path, flec->file_path, strlen(flec->file_path));
      strncat(full_path, flec->file_name, strlen(flec->file_name));
      text_buffer->append(full_path);
      Fineline_Log::print_log_entry("Fineline_Event_Dialog::add_marked_files() <INFO> added marked file.");
   }
   return;
}

void Fineline_Event_Dialog::put_file_metadata(fl_file_record_t *flrec)
{
   //TODO:
}

void Fineline_Event_Dialog::button_callback(Fl_Button *b, void *p)
{
   //TODO: get the calling button label and execute the required action

   ((Fineline_Event_Dialog *)p)->hide();
}


void Fineline_Event_Dialog::paste_cb(Fl_Widget *w, void* v) 
{
  Fineline_Event_Dialog* e = (Fineline_Event_Dialog*)v;
  Fl_Text_Editor::kf_paste(0, e->teditor);
}

void Fineline_Event_Dialog::copy_cb(Fl_Widget *w, void* v) 
{
  Fineline_Event_Dialog* e = (Fineline_Event_Dialog*)v;
  Fl_Text_Editor::kf_copy(0, e->teditor);
}

void Fineline_Event_Dialog::cut_cb(Fl_Widget *w, void* v) 
{
  Fineline_Event_Dialog* e = (Fineline_Event_Dialog*)v;
  Fl_Text_Editor::kf_cut(0, e->teditor);
}

void Fineline_Event_Dialog::delete_cb(Fl_Widget *w, void*) 
{
  text_buffer->remove_selection();
}


void Fineline_Event_Dialog::find_cb(Fl_Widget *w, void *v) 
{
   //TODO:
}

void Fineline_Event_Dialog::find_next_cb(Fl_Widget *w, void *v) 
{
   //TODO:
}

void Fineline_Event_Dialog::replace_cb(Fl_Widget *w, void *v) 
{
   //TODO:
}

void Fineline_Event_Dialog::replace_next_cb(Fl_Widget *w, void *v) 
{
   //TODO:
}

void Fineline_Event_Dialog::quit_cb(Fl_Widget *w, void *v) 
{
   //TODO:
}

void Fineline_Event_Dialog::close_cb(Fl_Widget *w, void *v) 
{
   //TODO:
}

void Fineline_Event_Dialog::open_cb(Fl_Widget *w, void *v) 
{
   //TODO:
}

void Fineline_Event_Dialog::insert_cb(Fl_Widget *w, void *v) 
{
   //TODO:
}

void Fineline_Event_Dialog::saveas_cb(Fl_Widget *w, void *v) 
{
   //TODO:
}

void Fineline_Event_Dialog::save_cb(Fl_Widget *w, void *v) 
{
   //TODO:
}