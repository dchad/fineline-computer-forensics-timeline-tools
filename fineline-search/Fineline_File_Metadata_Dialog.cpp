

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
   Fineline_File_Metadata_Dialog.cpp

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine FLTK GUI file metadata editor/exporter dialog.

   Notes: EXPERIMENTAL

*/

#include <FL/Fl_Text_Buffer.H>

#include "Fineline_File_Metadata_Dialog.h"


int                changed = 0;
char               filename[FL_PATH_MAX] = "";
char               title[FL_PATH_MAX];
Fl_Text_Buffer     *textbuf = 0;

#define TEXTSIZE 14

Fineline_File_Metadata_Dialog::Fineline_File_Metadata_Dialog(int x, int y, int w, int h) : Fl_Double_Window(x, y ,w, h, "File Metadata Editor")
{
   begin();

   Fl_Group* metadata_group = new Fl_Group(5, 5, w - 5, h - 5);
   metadata_group->tooltip("Edit the file metadata items and click the save button to write the metadata to a text file.");

   textbuf = new Fl_Text_Buffer;
   teditor = new Fl_Text_Editor(10, 10, w - 10, h - 50);
   teditor->textfont(FL_COURIER);
   teditor->textsize(TEXTSIZE);
   teditor->buffer(textbuf);
   textbuf->text();
   {
	   Fl_Button* o = new Fl_Button(w - 330, h - 40, 100, 30, "Save");
      o->callback((Fl_Callback*)button_callback, (void *)this);
      o->tooltip("Save metadata to the project file.");
   } // Fl_Button* o
   {
	   Fl_Button* o = new Fl_Button(w - 220, h - 40, 100, 30, "Save As");
      o->callback((Fl_Callback*)button_callback, (void *)this);
      o->tooltip("Save to a text file.");
   } // Fl_Button* o
   {
      Fl_Button* o = new Fl_Button(w - 120, h - 40, 100, 30, "Close");
      o->callback((Fl_Callback*)button_callback, (void *)this);
      o->tooltip("Close dialog without saving.");
   } // Fl_Button* o
   metadata_group->end();
   Fl_Group::current()->resizable(metadata_group);

   end();
}

Fineline_File_Metadata_Dialog::~Fineline_File_Metadata_Dialog()
{
   //dtor
}


void Fineline_File_Metadata_Dialog::button_callback(Fl_Button *b, void *p)
{
   ((Fineline_File_Metadata_Dialog *)p)->hide();
}

void Fineline_File_Metadata_Dialog::add_metadata(string metadata)
{
   textbuf->append(metadata.c_str());
   return;
}

void Fineline_File_Metadata_Dialog::add_metadata_file(string filename)
{
   textbuf->appendfile(filename.c_str());
   return;
}
