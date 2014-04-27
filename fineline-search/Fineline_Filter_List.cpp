
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

   Purpose:  Loads the file filter list into an STL vector. Each filter value can be
             a partial or full filename/path or just a keyword.

             Filter List Format: plain text file, place each file/keyword on a separate line.

             Examples:

             C:\temp
             exploit
             shellcode.bin
             warez.doc
             accounts.xls
             C:\temp\utils\exploit.txt


*/

#include <iostream>
#include <stdio.h>
#include <string.h>

#include "fineline-search.h"
#include "Fineline_Filter_List.h"

Fineline_Filter_List::Fineline_Filter_List()
{

}

Fineline_Filter_List::Fineline_Filter_List(string filename)
{
   if (load_filter_file() < 0)
   {
      cout << "Fineline_Filter_List() <ERROR> Could not open filter file " << filter_filename << endl;
   }
}

Fineline_Filter_List::~Fineline_Filter_List()
{
   //dtor
}

int Fineline_Filter_List::load_filter_file(string filename)
{
   filter_filename = filename;
   if (load_filter_file() < 0)
   {
      return(-1);
   }

   return(0);
}

/*
   Function: load_filter_file
   Purpose : loads the file filter list into a vector, returns -1 on load failure.
*/
int Fineline_Filter_List::load_filter_file()
{
   char instr[FL_MAX_INPUT_STR];
   FILE *filter_file;
   int filter_counter = 0;

   filter_file = fopen(filter_filename.c_str(), "r");
   if (filter_file == NULL)
   {
      printf("load_filter_file() <ERROR>: could not open filter file: %s\n", filter_filename.c_str());
      return(-1);
   }

   memset(instr, 0, FL_MAX_INPUT_STR);

   while (fgets(instr, FL_MAX_INPUT_STR, filter_file) != NULL)
   {
      string kword(trim(instr));
      filter_counter++;
      keyword_vector.push_back(kword);

      /* !!!CLEAR THE BUFFERS!!! */
      memset(instr, 0, FL_MAX_INPUT_STR);
   }

   printf("load_filter_filters() <INFO> Loaded %d filters.\n", filter_counter);

   fclose(filter_file);

   return(0);
}

int Fineline_Filter_List::add_keyword(string kword)
{
   keyword_vector.push_back(kword);
   return(0);
}

int Fineline_Filter_List::remove_keyword(string kword)
{
   return(0);
}

int Fineline_Filter_List::find_keyword(string kword)
{
   return(0);
}

int Fineline_Filter_List::sort_list()
{
   return(0);
}

int Fineline_Filter_List::match_filename(string filename)
{
   int result = -1;
   vector<string>::iterator p = keyword_vector.begin();

   while (p != keyword_vector.end())
   {
      if ((result = filename.find(*p)) >= 0)
      {
         break;
      }
      p++;
   }
   return(result);
}
