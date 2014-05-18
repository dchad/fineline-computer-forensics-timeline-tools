
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
   Fineline_File_System.h

   Title : FineLine Computer Forensics Tools
   Author: Derek Chadwick
   Date  : 28/04/2014

   Purpose: Class definition for a file system class that uses the
            Sleuth Kit library to analyse disk images.

   Notes: EXPERIMENTAL

*/


#ifndef FINELINE_FILE_SYSTEM_H
#define FINELINE_FILE_SYSTEM_H


#include <sys/stat.h>
#include <string>
#include <tsk/libtsk.h>
#include <FL/Fl.H>
#include <FL/Fl_Browser.H>

#include "Fineline_Log.h"
#include "Fineline_File_System_Tree.h"
#include "Fineline_Progress_Dialog.h"

using namespace std;


class Fineline_File_System
{
   public:
      Fineline_File_System(Fineline_File_System_Tree *ffst, string fs_image, Fineline_Progress_Dialog *fpd, Fineline_Log *log);
      ~Fineline_File_System();

      void start_task();
	   void stop_task();
	   int get_running();
      int open_forensic_image();
      int process_forensic_image();
      int close_forensic_image();
      void add_progress_text(char *msg);
      const char *get_image_name();
      void export_file(string file_path, string evidence_directory);
      void get_directory_contents(string path);

   protected:
   private:

      int make_path(string s, mode_t mode);

	   string fs_image;
};

#endif // FINELINE_FILE_SYSTEM_H
