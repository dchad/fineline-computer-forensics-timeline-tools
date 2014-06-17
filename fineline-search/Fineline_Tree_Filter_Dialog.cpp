
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
   Fineline_Tree_Filter_Dialog.cpp

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 10/06/2014

   Purpose: FineLine FLTK GUI file system tree file filter dialog.

   Notes: EXPERIMENTAL

*/

#include <FL/fl_ask.H>

#include "Fineline_Tree_Filter_Dialog.h"
#include "Fineline_Tree_Filter.h"

Fineline_Tree_Filter *tree_filter;

Fineline_Tree_Filter_Dialog::Fineline_Tree_Filter_Dialog(int x, int y, int w, int h) : Fl_Double_Window(x, y, w, h, "Fineline Filter Dialog")
{
   //ctor
   begin();

   Fl_Group* browser_group = new Fl_Group(10, 10, w - 10, h - 10);
   {
      textbuf = new Fl_Text_Buffer(FL_MAX_INPUT_STR);
      filter_file_field = new Fl_Input(100, 20, w - 160, 30, "Filter File:");
      filter_file_button = new Fl_Button(w - 50, 20, 30, 30, "File");
      filter_file_button->callback((Fl_Callback*)button_callback, (void *)this);
      keyword_editor = new Fl_Text_Editor(100, 70, w - 120, 210, "Keywords:");
      keyword_editor->align(FL_ALIGN_LEFT_TOP);
      keyword_editor->buffer(textbuf);
      progress_browser = new Fl_Browser(100, 300, w - 120, 210, "Progress:");
      progress_browser->align(FL_ALIGN_LEFT_TOP);
      Fl_Button* save_button = new Fl_Button(w - 360, h - 50, 100, 30, "Start");
      save_button->callback((Fl_Callback*)button_callback, (void *)this);
      Fl_Button* clear_button = new Fl_Button(w - 250, h - 50, 100, 30, "Clear");
      clear_button->callback((Fl_Callback*)button_callback, (void *)this);
      Fl_Button* close_button = new Fl_Button(w - 140, h - 50, 100, 30, "Close");
      close_button->callback((Fl_Callback*)button_callback, (void *)this);
   }
   browser_group->end();
   Fl_Group::current()->resizable(browser_group);

   end();
}

Fineline_Tree_Filter_Dialog::~Fineline_Tree_Filter_Dialog()
{
   //dtor
}

void Fineline_Tree_Filter_Dialog::button_callback(Fl_Button *b, void *p)
{
   Fineline_Tree_Filter_Dialog *ftfd = (Fineline_Tree_Filter_Dialog*)p;

   if (strncmp(b->label(), "Start", 5) == 0)
   {
      //TODO: start a thread to process the file system tree.
      ftfd->start_filter_thread();
   }
   else if (strncmp(b->label(), "Clear", 5) == 0)
   {
      // clear the fields and restore the original file system tree.
      ftfd->filter_file_field->value("");
      ftfd->progress_browser->clear();
      ftfd->textbuf->remove(0, ftfd->textbuf->length());
      ftfd->restore_tree();
   }
   else if (strncmp(b->label(), "Close", 5) == 0)
   {
      ftfd->hide();
   }

   return;
}

/*
   Name   : add_matched_file()
   Purpose: Called from the filter process thread to update the progress browser.
   Input  : String containing the file path.
   Output : None.
*/
void Fineline_Tree_Filter_Dialog::add_update_message(string filepath)
{
   progress_browser->add(filepath.c_str());
   progress_browser->bottomline(progress_browser->size());
   return;
}

/*
   Name   : start_filter_thread()
   Purpose: Creates a thread to perform a keyword filter of the file system tree.
   Input  : Pointer to this dialog and the file tree vector.
   Output : None.
*/
void Fineline_Tree_Filter_Dialog::start_filter_thread()
{
   string keywords = textbuf->text();

   if (tree_filter != NULL)
      delete tree_filter;

   tree_filter = new Fineline_Tree_Filter(file_system_tree, keywords, this);

   // Now start the filter processing thread.
   tree_filter->start_task();

   return;
}

void Fineline_Tree_Filter_Dialog::show_dialog(Fineline_File_System_Tree *ffst)
{
   // First make a copy of the file system map so we can revert back to the
   // original file system tree if the user removes the filter.
   file_system_tree = ffst;
   Fineline_File_Map fsm = file_system_tree->get_file_map();

   if (file_map.size() > 0)
      file_map.clear();

   if (fsm.size() > 0)
      file_map.insert(fsm.begin(), fsm.end());

   show();

   return;
}

void Fineline_Tree_Filter_Dialog::restore_tree()
{
   //TODO: restore the original file system tree.

   return;
}
