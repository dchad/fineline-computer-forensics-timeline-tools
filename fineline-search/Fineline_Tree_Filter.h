

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
   Fineline_Tree_Filter.cpp

   Title : FineLine Computer Forensics Tools
   Author: Derek Chadwick
   Date  : 28/04/2014

   Purpose: Class definition for filtering the file system tree with user supplied keywords.

   Notes: EXPERIMENTAL

*/



#ifndef FINELINE_TREE_FILTER_H
#define FINELINE_TREE_FILTER_H

#include <map>
#include <vector>

#include <sys/stat.h>
#include <string>
#include <tsk/libtsk.h>
#include <FL/Fl.H>
#include <FL/Fl_Browser.H>

#include "Fineline_File_System_Tree.h"
#include "Fineline_Tree_Filter_Dialog.h"

using namespace std;

class Fineline_Tree_Filter
{
   public:
      Fineline_Tree_Filter(Fineline_File_System_Tree *ffst, string keywords, Fineline_Tree_Filter_Dialog *ftd);
      virtual ~Fineline_Tree_Filter();

      void start_task();
	   void stop_task();
	   int get_running();
	   int process_file_system_tree();

   protected:
   private:

      Fineline_File_System_Tree *file_system_tree;
      vector < string > keyword_list;
      Fineline_File_Map file_map;

      int running;
};

#endif // FINELINE_TREE_FILTER_H
