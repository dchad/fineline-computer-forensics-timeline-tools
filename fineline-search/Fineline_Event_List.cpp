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
   Fineline_Filter_List.cpp

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 25/04/2014

   Purpose:  Stores a list of file names and metadata into an STL vector.

*/

#include "Fineline_Event_List.h"

using namespace std;

Fineline_Event_List::Fineline_Event_List()
{
   //ctor
}

Fineline_Event_List::~Fineline_Event_List()
{
   //dtor
}

int Fineline_Event_List::add_file_record(fl_file_record_t * flf)
{
   file_list.push_back(flf);

   return(file_list.size());
}

int Fineline_Event_List::delete_file_record(int record_index)
{

   return(0);
}

int Fineline_Event_List::find_file_record(string filename)
{
   return(0);
}

int Fineline_Event_List::sort_records()
{
   return(0);
}

int Fineline_Event_List::write_records()
{
   return(0);
}

int Fineline_Event_List::send_records()
{
   return(0);
}

int Fineline_Event_List::list_size()
{
   return(file_list.size());
}

int Fineline_Event_List::clear_list()
{
   //fl_file_record_t *p;
   //unsigned int i;

   //for (i = 0; i < file_list.size(); i++)
   //{
   //   p = file_list[i];
   //   xfree((char *)p, sizeof(fl_file_record_t));
   //}

   file_list.clear();

   return(file_list.size());
}
