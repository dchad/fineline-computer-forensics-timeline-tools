
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

#include <string>
#include <tsk/libtsk.h>

#include "fineline-search.h"

using namespace std;


class Fineline_File_System
{
   public:
      Fineline_File_System(Fineline_Log *log);
      ~Fineline_File_System();

      int open_file_system_image(string fs_image);
      int parse_file_system_image();
      int close_file_system_image();

   protected:
   private:

      TskImgInfo *image_info;
	  Fineline_Log *flog;
};

#endif // FINELINE_FILE_SYSTEM_H
