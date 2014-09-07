
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
   Fineline_File_System_Tree.h

   Title : FineLine Computer Forensics Image Search file browser tree
   Author: Derek Chadwick
   Date  : 05/05/2014

   Purpose: Displays a file system in a tree widget.

   Notes: EXPERIMENTAL

*/


#ifndef FINELINE_FILE_SYSTEM_TREE_H
#define FINELINE_FILE_SYSTEM_TREE_H

#include <string>
#include <vector>
#include <map>

#include <FL/Fl.H>
#include <FL/Fl_Tree.H>

#include "fineline-search.h"
#include "Fineline_Progress_Dialog.h"

using namespace std;

typedef map< string, fl_file_record_t* > Fineline_File_Map;

class Fineline_File_System_Tree : public Fl_Tree
{
   public:

      Fineline_File_System_Tree(int x, int y, int w, int h);
      virtual ~Fineline_File_System_Tree();

      static void file_system_tree_callback(Fl_Tree *flt, void *p);
      int add_file(string filename, fl_file_record_t *flrp);
      void add_file_nodes(string file_path);
      void add_file_map(Fineline_File_Map &fmap);
      fl_file_record_t *find_file(string filename);
      fl_file_record_t *get_file_record(const char *file_path);
      fl_file_record_t *get_selected_file_record();
      void mark_file(string filename);
      void mark_file();
      void unmark_file();
      void unmark_children(Fl_Tree_Item *flti);
      void mark_children(Fl_Tree_Item *flti);
      vector< fl_file_record_t* > get_marked_files();
      Fineline_File_Map get_file_map();
      int remove_file(string filename);
      int tree_size();
      int clear_tree();
      int save_tree(Fineline_Progress_Dialog *pd, const char *filename);
      int print_tree();
      void assign_user_icons();
      void rebuild_tree();


   protected:
   private:

      Fineline_File_Map file_map;

};

#endif // FINELINE_FILE_SYSTEM_TREE_H
