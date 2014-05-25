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
   fineline-search.h

   Title : FineLine Computer Forensics Windows Search Cache Parser
   Author: Derek Chadwick
   Date  : 02/03/2014

   Purpose: FineLine global definitions.

*/

#ifndef FINELINE_SEARCH_H
#define FINELINE_SEARCH_H

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#include "../common/flcommon.h"

enum FL_FILE_TYPES { FL_DIRECTORY = 1, FL_NORMAL_FILE, FL_SYSTEM_FILE };

struct fl_file_record
{
   int id;
   int marked;
   int hidden;
   long creation_time;
   long access_time;
   long modification_time;
   long file_size;
   int  file_type;
   char file_access_time_string[32];
   char file_creation_time_string[32];
   char file_modification_time_string[32];
   char file_owner[256];
   char file_name[256];
   char file_path[FL_MAX_INPUT_STR];
   char file_event_string[FL_MAX_INPUT_STR];
};

typedef struct fl_file_record fl_file_record_t;


/*
   Function Prototypes
*/

/* fineline-search.c */
int parse_command_line_args(int argc, char *argv[], char *fl_filename, char *in_file, char *gui_ip_address, char *filter_filename);

#endif
