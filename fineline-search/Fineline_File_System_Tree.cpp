
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
   Fineline_File_System_Tree.cpp

   Title : FineLine Computer Forensics Image Search file browser tree
   Author: Derek Chadwick
   Date  : 05/05/2014

   Purpose: Displays a file system in a tree widget.

   Notes: EXPERIMENTAL

*/






#include "Fineline_File_System_Tree.h"

Fineline_File_System_Tree::Fineline_File_System_Tree(int x, int y, int w, int h) : Fl_Tree(x, y, w, h, "File System")
{

   tooltip("Test tree");
   box(FL_DOWN_BOX);
   color((Fl_Color)55);
   selection_color(FL_SELECTION_COLOR);
   labeltype(FL_NORMAL_LABEL);
   labelfont(0);
   labelsize(14);
   labelcolor(FL_FOREGROUND_COLOR);
   callback((Fl_Callback*)file_system_tree_callback, (void*)(1234));
   align(Fl_Align(FL_ALIGN_TOP));
   when(FL_WHEN_RELEASE);
   end();

}

Fineline_File_System_Tree::~Fineline_File_System_Tree()
{
   //dtor
}

void Fineline_File_System_Tree::file_system_tree_callback(Fl_Tree *flt, void *vp)
{

   return;
}

int Fineline_File_System_Tree::add_file(string filename, fl_file_record_t *flrp)
{
   return(0);
}


