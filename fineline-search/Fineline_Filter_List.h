
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
   Fineline_Filter_List.h

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


#ifndef FINELINE_FILTER_LIST_H
#define FINELINE_FILTER_LIST_H

#include <vector>
#include <string>

#include "Fineline_Util.h"

using namespace std;

class Fineline_Filter_List
{
   public:

      Fineline_Filter_List();
      Fineline_Filter_List(string filename);
      virtual ~Fineline_Filter_List();

      int load_filter_file();
      int load_filter_file(string filename);
      int add_keyword(string kword);
      int remove_keyword(string kword);
      int find_keyword(string kword);
      int match_filename(string filename);
      int sort_list();

   protected:
   private:

      vector<string> keyword_vector;
      string filter_filename;
      Fineline_Util flut;
};

#endif // FINELINE_FILTER_LIST_H
