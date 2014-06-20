
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

   Purpose: Displays a file system in a tree widget, the file records are stored
            in a map for fast lookups based on the filename key value. This allows
            easy mapping from the FLTK tree nodes to the corresponding file records.

   Notes: EXPERIMENTAL

*/


#include <stdio.h>
#include <iostream>

#include <tsk/libtsk.h>

#include <FL/fl_ask.H>
#include <FL/filename.H>

#include "Fineline_Log.h"
#include "Fineline_File_System_Tree.h"

using namespace std;

Fineline_File_System_Tree::Fineline_File_System_Tree(int x, int y, int w, int h) : Fl_Tree(x, y, w, h)
{

   begin();
   tooltip("File System Browser");
   box(FL_DOWN_BOX);
   color((Fl_Color)55);
   selection_color(FL_SELECTION_COLOR);
   labeltype(FL_NORMAL_LABEL);
   labelfont(0);
   labelsize(14);
   labelcolor(FL_FOREGROUND_COLOR);
   align(Fl_Align(FL_ALIGN_TOP));
   //callback((Fl_Callback *)file_system_tree_callback);
   when(FL_WHEN_RELEASE);
   end();

}

Fineline_File_System_Tree::~Fineline_File_System_Tree()
{
   //dtor
}

/*
   Unit testing only.
*/
void Fineline_File_System_Tree::file_system_tree_callback(Fl_Tree *flt, void *p)
{
	Fl_Tree_Item * flti = flt->item_clicked();
   cout << "Clicked on: " << flti->label() << endl;
   return;
}

/*
   Name   : add_file()
   Purpose: Add a node to the file system tree widget and store the
            file metadata record in the file map.
   Input  : File path of the node, file metadata record pointer.
   Output : None.
*/
int Fineline_File_System_Tree::add_file(string filename, fl_file_record_t *flrp)
{
   // Only add file leaf nodes to the tree if running on Linux,
   // Windows has performance issues if there are more than 20000 nodes,
   // This results in noticable delays when clicking on tree nodes,
   // so do dynamic leaf node addition when running one Windoze.

#ifdef LINUX_BUILD
   add(filename.c_str());
   close(filename.c_str(), 0);
#else
   // Windows major culprit is the winsxs directory containing backups of updated system files.
   // So add the winsxs directory but leave all the subdirectories for addition by user selection.
   unsigned int pos;
   pos = filename.find("winsxs");
   if (pos == string::npos)
   {
      add(filename.c_str());
      close(filename.c_str(), 0);
   }
   else if ((filename.size() - pos) < 7)
   {
      add(filename.c_str());
      close(filename.c_str(), 0);
   }
#endif

   file_map[filename] = flrp;
   return(file_map.size());
}


/*
   Name   : add_file_nodes()
   Purpose: Dynamically add file leaf nodes to the tree on Windows
            systems only. Not required on Linux, needed on Windows due
            to performance issues displaying large file system trees.
            Only use for the winsxs directory.
   Input  : File path of the directory node.
   Output : None.
*/
void Fineline_File_System_Tree::add_file_nodes(string file_path)
{
   char path[FL_PATH_MAX];
   int path_len = file_path.size();

   if (file_path.find("winsxs") == string::npos)
   {
      return; // Not a winsxs subdirectory
   }
   if (file_path.compare(0, 4, "ROOT") == 0)
   {
      file_path.erase(0, 5);  // Remove the tree ROOT/ label and path separator
   }
   strncpy(path, file_path.c_str(), path_len);
   map< string, fl_file_record_t* >::iterator p = file_map.begin();

   while (p != file_map.end())
   {
      fl_file_record_t *flec = p->second;

      if (strncmp(flec->file_path, path, path_len) == 0)
      {
         add(flec->full_path);
      }
      p++;
   }
}


/*
   Name   : add_file_map()
   Purpose: Add a file map to the file system tree. Called from the search, filter
          : and import dialogues to create or restore the file system tree.
   Input  : File map containing records or every file in the file system.
   Output : None.
*/
void Fineline_File_System_Tree::add_file_map(Fineline_File_Map &fmap)
{
   // First clear the file system tree, copy the import map to our local map,
   // then iterate over the map and add each node to file system tree.
   clear();
   file_map = fmap;
   map< string, fl_file_record_t* >::iterator p = fmap.begin();

   while (p != fmap.end())
   {
      fl_file_record_t *flec = p->second;
      add(flec->full_path);
      p++;
   }
}

/*
   Name   : find_file()
   Purpose: Lookup the file metadata record in the file map.
   Input  : File path of the node.
   Output : Pointer to the file metadata record or NULL.
*/
fl_file_record_t *Fineline_File_System_Tree::find_file(string filename)
{
   if (filename.compare(0, 4, "ROOT") == 0)
   {
      filename.erase(0, 5);  // Remove the tree ROOT/ label and path separator
   }
   map< string, fl_file_record_t* >::iterator p = file_map.find(filename);

   if(p == file_map.end())
   {
      cout << "Fineline_File_System_Tree::find_file() <INFO> " << filename << " is not in the tree." << endl;
      return(NULL);
   }
   return(p->second);
}

/*
   Name   : remove_file()
   Purpose: Delete the file metadata record from the file map.
   Input  : File path of the file system tree node.
   Output : Returns the map size.
*/
int Fineline_File_System_Tree::remove_file(string filename)
{
   //TODO:
   return(file_map.size());
}

int Fineline_File_System_Tree::save_tree(Fineline_Progress_Dialog *pd, const char *filename)
{
   // Open the output file and iterate through the file map and write out each node.
   string msg;
   char file_path[FL_MAX_INPUT_STR];
   Fl_Tree_Item *tip = first();
   FILE *fp = fopen(filename, "w");

   if (fp == NULL)
   {
	   msg = "save_tree() <ERROR>: Could not create file: ";
	   msg.append(filename);
	   Fineline_Log::print_log_entry(msg.c_str());
      return(-1);
   }

   msg = "Saving file system tree to file: ";
   msg.append(filename);
   pd->add_progress_message(msg);
   for (tip = first(); tip; tip = next(tip))
   {
      item_pathname(file_path, FL_MAX_INPUT_STR, tip);
      fprintf(fp, "%s\n", file_path);
      pd->add_progress_message(file_path);
   }

   fclose(fp);

   msg = "Finished saving file system tree.";
   pd->add_progress_message(msg);

   return(0);
}

int Fineline_File_System_Tree::print_tree()
{
   //TODO:
   return(0);
}

/*
   Name   : tree_size()
   Purpose: Get the tree size.
   Input  : None.
   Output : Returns the file map size.
*/
int Fineline_File_System_Tree::tree_size()
{
   return(file_map.size());
}

/*
   Name   : clear_tree()
   Purpose: Empty the file system tree and the file metadata map.
   Input  : None.
   Output : Returns the file map size.
*/
int Fineline_File_System_Tree::clear_tree()
{
   clear();
   file_map.clear();
   return(file_map.size());
}

void Fineline_File_System_Tree::assign_user_icons()
{
  static const char *L_folder_xpm[] = {
      "11 11 3 1",
      ".  c None",
      "x  c #d8d833",
      "@  c #808011",
      "...........",
      ".....@@@@..",
      "....@xxxx@.",
      "@@@@@xxxx@@",
      "@xxxxxxxxx@",
      "@xxxxxxxxx@",
      "@xxxxxxxxx@",
      "@xxxxxxxxx@",
      "@xxxxxxxxx@",
      "@xxxxxxxxx@",
      "@@@@@@@@@@@"};
  static Fl_Pixmap L_folderpixmap(L_folder_xpm);

   static const char *L_document_xpm[] = {
      "11 11 3 1",
      ".  c None",
      "x  c #d8d8f8",
      "@  c #202060",
      ".@@@@@@@@@.",
      ".@xxxxxxx@.",
      ".@xxxxxxx@.",
      ".@xxxxxxx@.",
      ".@xxxxxxx@.",
      ".@xxxxxxx@.",
      ".@xxxxxxx@.",
      ".@xxxxxxx@.",
      ".@xxxxxxx@.",
      ".@xxxxxxx@.",
      ".@@@@@@@@@."};
   static Fl_Pixmap L_documentpixmap(L_document_xpm);

  // Assign user icons to tree items
   for ( Fl_Tree_Item *item = first(); item; item=item->next())
   {
      item->usericon(item->has_children() ? &L_folderpixmap : &L_documentpixmap);
   }

}

void Fineline_File_System_Tree::rebuild_tree()
{
   assign_user_icons();
   redraw();
}


fl_file_record_t *Fineline_File_System_Tree::get_selected_file_record()
{
   //TODO: string selected_file_path = ???
   return(NULL);
}

fl_file_record_t *Fineline_File_System_Tree::get_file_record(const char *file_path)
{
   string fp;

   fp = file_path;

   return(find_file(fp));
}

/*
   Name   : mark_file()
   Purpose: Set the marked attribute in the file metadata record.
   Input  : File tree path.
   Output : None.
*/
void Fineline_File_System_Tree::mark_file(string filename)
{
   fl_file_record_t *flec = find_file(filename);

   if (flec != NULL)
      flec->marked = 1;

   return;
}

/*
   Name   : mark_file()
   Purpose: Set the marked attribute in the file metadata record.
            Gets the first selected item for the file system tree
            widget and looks up the file metadata record.
   Input  : None.
   Output : None.
*/
void Fineline_File_System_Tree::mark_file()
{
	Fl_Tree_Item *flti = first_selected_item();
   fl_file_record_t *flrec = NULL;
   char file_path[FL_PATH_MAX]; // FL_PATH_MAX 2048 is an FLTK constant, Fineline FL_PATH_MAX_LENGTH 4096
   string full_path;

   if (flti != 0)
   {
      if (item_pathname(file_path, FL_PATH_MAX, flti) != 0)
      {
         Fineline_Log::print_log_entry("Fineline_File_System_Tree::mark_file() <ERROR> Could not get tree item path.");
         fl_message(" <ERROR> Could not get tree item. ");
          return;
      }

      full_path.append(file_path);
      flrec = find_file(full_path);
      if (flrec != NULL)
      {
         flrec->marked = 1;
         flti->labelcolor(FL_DARK_GREEN);
         flti->labelfont(FL_COURIER_BOLD);
         Fl::awake();
         Fineline_Log::print_log_entry("Fineline_File_System_Tree::mark_file() <INFO> marked file.");
      }
   }
   return;
}

void Fineline_File_System_Tree::unmark_file()
{
	Fl_Tree_Item *flti = first_selected_item();
   fl_file_record_t *flrec = NULL;
   char file_path[FL_PATH_MAX]; // FL_PATH_MAX 2048 is an FLTK constant, Fineline FL_PATH_MAX_LENGTH 4096
   string full_path;

   if (flti != 0)
   {
      if (item_pathname(file_path, FL_PATH_MAX, flti) != 0)
      {
         Fineline_Log::print_log_entry("Fineline_File_System_Tree::unmark_file() <ERROR> Could not get tree item path.");
         fl_message(" <ERROR> Could not get tree item. ");
          return;
      }

      full_path.append(file_path);
      flrec = find_file(full_path);
      if (flrec != NULL)
      {
         flrec->marked = 0;
         flti->labelcolor(FL_FOREGROUND_COLOR);
         flti->labelfont(FL_COURIER);
         Fl::awake();
      }
   }
   return;
}

vector< fl_file_record_t* > Fineline_File_System_Tree::get_marked_files()
{
   vector< fl_file_record_t* > flist;

   map < string, fl_file_record_t* >::iterator p = file_map.begin();

   while (p != file_map.end())
   {
      if (p->second->marked == 1)
         flist.push_back(p->second);
      p++;
   }

   return(flist);
}

map< string, fl_file_record_t* > Fineline_File_System_Tree::get_file_map()
{
   return(file_map);
}
