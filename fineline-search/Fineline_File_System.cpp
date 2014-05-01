
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
   Fineline_File_System.cpp

   Title : FineLine Computer Forensics Tools
   Author: Derek Chadwick
   Date  : 28/04/2014

   Purpose: Class implementation for a file system class that uses the
            Sleuth Kit library to analyse disk images.

   Notes: EXPERIMENTAL

*/



#include "Fineline_File_System.h"


Fineline_File_System::Fineline_File_System(Fineline_Log *log)
{
   flog = log;
}

Fineline_File_System::~Fineline_File_System()
{
   //dtor
}

int Fineline_File_System::open_file_system_image(string fs_image)
{
   int ret_val = 0;

   image_info = new TskImgInfo();

   if (image_info->open(fs_image.c_str(), TSK_IMG_TYPE_DETECT, 0) == 1)
   {
      delete image_info;
      flog->print_log_entry("Error opening file\n");
      ret_val = -1;
    }
   return(ret_val);
}

int Fineline_File_System::parse_file_system_image()
{
   return(0);
}

int Fineline_File_System::close_file_system_image()
{
   return(0);
}

