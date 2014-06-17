

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

   Purpose: Class implementation for filtering the file system tree with user supplied keywords.

   Notes: EXPERIMENTAL

*/


#include "../common/threads.h"

#include "Fineline_Tree_Filter.h"
#include "../common/Fineline_Util.h"
#include "Fineline_Log.h"

Fineline_Tree_Filter_Dialog *tree_filter_dialog;

Fineline_Tree_Filter::Fineline_Tree_Filter(Fineline_File_System_Tree *ffst, string keywords, Fineline_Tree_Filter_Dialog *ftd)
{
   //ctor
   file_system_tree = ffst;
   file_map.insert(file_system_tree->get_file_map().begin(), file_system_tree->get_file_map().end());
   tree_filter_dialog = ftd;

   // Now tokenize the keywords into a vector.
   Fineline_Util::split(keyword_list, keywords);

   running = 0;
}

Fineline_Tree_Filter::~Fineline_Tree_Filter()
{
   //dtor
}

static void progress_message(const char *msg_str)
{
   string msg(msg_str);
   Fl::lock();
   tree_filter_dialog->add_update_message(msg);
   Fl::unlock();
   return;
}

static void put_progress_message(string msg)
{
   Fl::lock();
   tree_filter_dialog->add_update_message(msg);
   Fl::unlock();
   return;
}

/*
   Function: thread_task
   Purpose : Worker function for the posix/win32 thread, must be a C function.
   Input   : Pointer to the file system tree filter object.
   Output  : Returns NULL.
*/
void *fl_thread_task(void *p)
{
   Fineline_Tree_Filter *file_tree_filter = (Fineline_Tree_Filter *)p;

   file_tree_filter->process_file_system_tree();

   return(NULL);
}



/*
   Function: start_task
   Purpose : Starts the worker function for the posix/win32 thread.
             Recommended method for processing large file system trees.
   Input   : the work function name and a pointer to this.
   Output  : None.
*/
void Fineline_Tree_Filter::start_task()
{
	running = 1;
	Fl_Thread thread_id;
	fl_create_thread(thread_id, fl_thread_task, (void *)this);
}

void Fineline_Tree_Filter::stop_task()
{
	running = 0;
}

int Fineline_Tree_Filter::get_running()
{
	return(running);
}

/*
   Method  : process_file_system_tree
   Purpose : Performs the filtering of the file system tree by matching file paths
           : with the keyword list. Called from the POSIX thread worker function.
   Input   : The file system tree and file map.
   Output  : Adds nodes to the file system tree GUI widget and progress messages
           : to the tree filter dialogue.
*/
int Fineline_Tree_Filter::process_file_system_tree()
{
   //char msg[256];
   string pmsg;
   //bool completed = false;
   int i, keyword_list_size = keyword_list.size();

   Fineline_Log::print_log_entry("fl_thread_task() <INFO> Started tree filter processing thread.\n");

   file_system_tree->clear_tree();

   map< string, fl_file_record_t* >::iterator p = file_map.begin();

   while (p != file_map.end())
   {
      // Iterate through the file system map and compare each file name with each keyword,
      // if a match then add to the file system tree and put a progress message on the dialog.
      fl_file_record_t *flec = p->second;
      string full_path = flec->file_path;
      full_path.append(flec->file_path);

      for (i = 0; i < keyword_list_size; i++)
      {
         if (full_path.find(keyword_list[i], 0) != string::npos)
         {
            file_system_tree->add_file(full_path, flec);
         }
      }
   }

   Fl::awake();

   file_system_tree->rebuild_tree();

   pmsg = "-----------------------------------------------------------------------------------";
   put_progress_message(pmsg);
   pmsg = "Completed rebuilding file system tree.";
   put_progress_message(pmsg);
   pmsg = "-----------------------------------------------------------------------------------";
   put_progress_message(pmsg);

   Fl::awake();

   return(0);
}
