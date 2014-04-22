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
   flfiltermap.c

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 10/03/2014

   Purpose:  Loads in the url filter list file into a hashmap. Each filter value can be 
             a partial or full URL or just a keyword.

             Filter List Format: plain text file, place each URL/keyword on a separate line.

             URL = protocol://domain/path?query_string
             
             Examples:

             http://www.hackerheaven.net/
             file:///C:/stuff/file.txt
             exploit
             shellcode
             warez
             accounts.xls
             www.cultofthedeadcow.net

*/

#include <stdio.h>
#include <string.h>

#include "fineline-iepre10.h"

struct fl_url_filter *filters = NULL; /* head of the hashmap, used in all the macro calls */


void add_filter(int url_id, struct fl_url_filter *flurl)
{
    struct fl_url_filter *s;

    HASH_FIND_INT(filters, &url_id, s);  /* id already in the hash? */
    if (s == NULL) 
    {
      HASH_ADD_INT(filters, url_id, flurl);  /* id: name of key field */
    }

}

struct fl_url_filter *find_filter(int url_id) 
{
    struct fl_url_filter *s;

    HASH_FIND_INT(filters, &url_id, s);  /* s: output pointer */
    return s;
}

int match_url_filter(char *url_string) 
{
    struct fl_url_filter *s;

    for(s=filters; s != NULL; s=(struct fl_url_filter *)(s->hh.next)) 
    {
        if (strstr(url_string, s->url_string) != NULL)
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
int load_url_filters(char *filter_filename)
{
   char instr[FL_MAX_INPUT_STR];
   FILE *filter_file;
   struct fl_url_filter *flurl;
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

      flurl = (struct fl_url_filter *)xcalloc(sizeof(struct fl_url_filter));

      filter_counter++;
      rtrim(instr);
      flurl->url_id = filter_counter;
      strncpy(flurl->url_string, instr, strlen(instr));
      add_filter(flurl->url_id, flurl);

      /* !!!CLEAR THE BUFFERS!!! */
      memset(instr, 0, FL_MAX_INPUT_STR);
   }

   printf("load_url_filters() <INFO> Loaded %d URL filters.\n", filter_counter);

   fclose(filter_file);

   return(0);
}

