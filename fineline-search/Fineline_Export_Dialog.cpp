

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

#include <FL/filename.H>

#include "Fineline_Log.h"
#include "Fineline_Util.h"
#include "Fineline_Export_Dialog.h"


Fineline_Export_Dialog::Fineline_Export_Dialog(int x, int y, int w, int h) : Fl_Double_Window(x, y, w, h, "Fineline Export Dialog")
{
   begin();

   Fl_Group* browser_group = new Fl_Group(10, 10, w - 10, h - 10);
   {
      file_browser = new Fl_Browser(20, 20, w - 40, h - 100);
      evidence_directory_field = new Fl_File_Input(100, h - 50, 250, 30, "Directory:");
      evidence_directory_field->value("./evidence");
      export_button = new Fl_Button(w - 250, h - 50, 100, 30, "Start");
      export_button->callback((Fl_Callback*)button_callback, (void *)this);
      close_button = new Fl_Button(w - 140, h - 50, 100, 30, "Close");
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
   // if export button call the file system object to export the marked files
   Fineline_Export_Dialog *fed = (Fineline_Export_Dialog *)p;

   if (strncmp(b->label(), "Start", 5) == 0)
   {
      fed->export_files();
   }
   else
   {
      fed->file_browser->clear();
      fed->hide();
   }

   return;
}

void Fineline_Export_Dialog::add_marked_files(vector< fl_file_record_t* > flist, Fineline_File_System *ffs)
{
   unsigned int i;
   char full_path[FL_PATH_MAX];
   marked_file_list = flist;
   file_system = ffs;
   string msg;

   msg = "--------------------------------------------------------------------------------------------";
   file_browser->add(msg.c_str());
   msg = "Export marked files.";
   file_browser->add(msg.c_str());
   msg = "--------------------------------------------------------------------------------------------";
   file_browser->add(msg.c_str());

   for (i = 0; i < marked_file_list.size(); i++)
   {
      memset((void*)full_path, 0, FL_PATH_MAX);
      fl_file_record_t *flec = marked_file_list[i];
      strncpy(full_path, flec->file_path, strlen(flec->file_path));
      strncat(full_path, flec->file_name, strlen(flec->file_name));
      file_browser->add(full_path);
      if (DEBUG)
         Fineline_Log::print_log_entry("Fineline_Export_Dialog::add_marked_files() <INFO> added marked file.");
   }

   msg = "--------------------------------------------------------------------------------------------";
   file_browser->add(msg.c_str());
   msg = "Enter a destination directory and click Start to begin file extraction.";
   file_browser->add(msg.c_str());
   msg = "--------------------------------------------------------------------------------------------";
   file_browser->add(msg.c_str());

   return;
}

void Fineline_Export_Dialog::export_files()
{
   string evidence_directory;
   unsigned int i;
   string full_path;
   string msg;

   evidence_directory = evidence_directory_field->value();

   for (i = 0; i < marked_file_list.size(); i++)
   {
      fl_file_record_t *flec = marked_file_list[i];
      full_path.append(flec->file_path);
      full_path.append(flec->file_name);
      if (file_system->export_file(full_path, evidence_directory) == 0)
      {
         msg = "Exported file: ";
         msg.append(full_path);
         file_browser->add(msg.c_str());
      }
      full_path.clear();
      if (DEBUG)
         Fineline_Log::print_log_entry("Fineline_Export_Dialog::export_files() <INFO> export marked file.");
   }

   return;
}
