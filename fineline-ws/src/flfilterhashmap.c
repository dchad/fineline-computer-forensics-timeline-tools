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
   flfilterhashmap.c

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 10/04/2014

   Purpose:  Loads in the file filter list into a hashmap. Each filter value can be
             a partial or full filename/path or just a keyword.

             Filter List Format: plain text file, place each file/keyword on a separate line.

             Examples:

             file:///C:/stuff/file.txt
             exploit
             shellcode.bin
             warez.doc
             accounts.xls
             C:\temp\utils\exploit.txt

*/

#include <stdio.h>
#include <string.h>

#include "fineline-ws.h"

struct fl_file_filter *filters = NULL; /* head of the hashmap, used in all the macro calls */


void add_filter(int file_id, struct fl_file_filter *flf)
{
    struct fl_file_filter *s;

    HASH_FIND_INT(filters, &file_id, s);  /* id already in the hash? */
    if (s == NULL)
    {
      HASH_ADD_INT(filters, file_id, flf);  /* id: name of key field */
    }

}

struct fl_file_filter *find_filter(int file_id)
{
    struct fl_file_filter *s;

    HASH_FIND_INT(filters, &file_id, s);  /* s: output pointer */
    return s;
}

int match_file_filter(char *file_string)
{
    struct fl_file_filter *s;

    for(s=filters; s != NULL; s=(struct fl_file_filter *)(s->hh.next))
    {
        if (strstr(file_string, s->file_string) != NULL)
           return(1); /* we have a match for one of the filter strings */
    }
    return(0);
}

/*
   Function: load_url_filters
   Purpose : loads in the event filter list file and sets the filter flags
             in the windows event list hashmap. Note the event hashmap must be
             loaded before the filter hashmap is loaded or nothing will be set.
*/
int load_file_filters(char *filter_filename)
{
   char instr[FL_MAX_INPUT_STR];
   FILE *filter_file;
   struct fl_file_filter *flf;
   int filter_counter = 0;

   filter_file = fopen(filter_filename, "r");
   if (filter_file == NULL)
   {
      printf("load_url_filters() <ERROR>: could not open event file: %s\n", filter_filename);
      return(-1);
   }

   memset(instr, 0, FL_MAX_INPUT_STR);

   while (fgets(instr, FL_MAX_INPUT_STR, filter_file) != NULL)
   {

      flf = (struct fl_file_filter *)xcalloc(sizeof(struct fl_file_filter));

      filter_counter++;
      rtrim(instr);
      flf->file_id = filter_counter;
      strncpy(flf->file_string, instr, strlen(instr));
      add_filter(flf->file_id, flf);

      /* !!!CLEAR THE BUFFERS!!! */
      memset(instr, 0, FL_MAX_INPUT_STR);
   }

   printf("load_url_filters() <INFO> Loaded %d URL filters.\n", filter_counter);

   fclose(filter_file);

   return(0);
}

