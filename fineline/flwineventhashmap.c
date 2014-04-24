


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
   flwineventhashmap.c

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 22/12/2013

   Purpose: Wrapper functions for uthash by Troy Hanson. Use to implement
            a hashmap for Windows Event IDs to be used for filtering
            events while processing input event logs. The events of interest
            are mostly in the Security.evtx event log.

*/

#include <stdio.h>
#include <string.h>

#include "fineline.h"

struct fl_windows_event_id *events = NULL; /* the hash map head record */

void add_windows_event_id_record(int event_id, struct fl_windows_event_id *flep)
{
    struct fl_windows_event_id *s;

    HASH_FIND_INT(events, &event_id, s);  /* id already in the hash? */
    if (s == NULL) 
	 {
      HASH_ADD_INT( events, id, flep );  /* id: name of key field */
    }

}

struct fl_windows_event_id *find_windows_event_id(int event_id) 
{
    struct fl_windows_event_id *s;

    HASH_FIND_INT(events, &event_id, s);  /* s: output pointer */
    return s;
}

void delete_windows_event_id(struct fl_windows_event_id *event_record) 
{
    HASH_DEL( events, event_record);  /* event: pointer to deletee */
    free(event_record);
}

void delete_all_event_ids() 
{
  struct fl_windows_event_id *current_event, *tmp;

  HASH_ITER(hh, events, current_event, tmp) 
  {
    HASH_DEL(events,current_event);  /* delete it (events advances to next) */
    free(current_event);            /* free it */
  }
}

void set_all_event_filters(int filter_val) 
{
  struct fl_windows_event_id *current_event, *tmp;

  HASH_ITER(hh, events, current_event, tmp) 
  {
    current_event->filter_out = filter_val;
  }
}

void print_event_ids() 
{
    struct fl_windows_event_id *s;

    for(s=events; s != NULL; s=(struct fl_windows_event_id *)(s->hh.next)) 
	{
        printf("Event ID %d : Description %s\n", s->id, s->event_description);
    }
}

int description_sort(struct fl_windows_event_id *a, struct fl_windows_event_id *b) 
{
    return strcmp(a->event_description,b->event_description);
}

int id_sort(struct fl_windows_event_id *a, struct fl_windows_event_id *b) {
    return (a->id - b->id);
}

void sort_by_name() 
{
    HASH_SORT(events, description_sort);
}

void sort_by_id() 
{
    HASH_SORT(events, id_sort);
}

/* 
   Function: load_event_hashmap
   Purpose : loads in the windows event list file to be used during event record
             parsing and filtering.
*/
int load_windows_event_id_hashmap()
{
	char instr[FL_MAX_INPUT_STR];
	FILE *event_file;
	struct fl_windows_event_id *flwe;
   char *token = NULL;
	int event_counter = 0;

   event_file = fopen(WINDOWS_EVENT_LIST, "r");
   if (event_file == NULL)
   {
       printf("load_hashmap() <ERROR>: could not open event file: %s\n", WINDOWS_EVENT_LIST);
		 return(-1);
   }
    
   memset(instr, 0, FL_MAX_INPUT_STR); /* !!!CLEAR THE BUFFERS!!! */

	while (fgets(instr, FL_MAX_INPUT_STR, event_file) != NULL)
	{
		int index;
		flwe = (struct fl_windows_event_id *)xcalloc(sizeof(struct fl_windows_event_id));
		flwe->event_id_string = (char *)xcalloc(MAX_EVENT_ID_SIZE);
		flwe->event_description = (char *)xcalloc(MAX_EVENT_DESC_SIZE);

		index = strcspn(instr, " ");
		if ((index == 0) || (index > MAX_EVENT_ID_SIZE))
		{
			printf("load_hashmap() <ERROR> Invalid windows event list entry!\n");
            continue;
		}
		strncpy(flwe->event_id_string, instr, index+1);

		token = strchr(instr, ' ');
      if ((token == NULL) || (strlen(token) > MAX_EVENT_DESC_SIZE))
      {
         printf("load_hashmap() <ERROR> Invalid windows event list entry!\n");
         continue;
      }
      /* DEPRECATED: does not work on Linux  token[strlen(token)-1] = 0;  get rid of the newline */
      rtrim(token);
      strncpy(flwe->event_description, token, strlen(token));
		
      flwe->id = atoi(flwe->event_id_string);
      flwe->year =       0;
      flwe->month =      0;
      flwe->day =        0;
      flwe->hour =       0;
      flwe->minute =     0;
      flwe->second =     0;
      flwe->filter_out = 0; /* 0 = DO NOT FILTER, 1 = FILTER OUT */

		add_windows_event_id_record(flwe->id, flwe);

		event_counter++;
      memset(instr, 0, FL_MAX_INPUT_STR); /* !!!CLEAR THE BUFFERS!!! */
	}
	
   fclose(event_file);

	return(0);
}


int compare_events(struct fl_windows_event_id *fled1, struct fl_windows_event_id *fled2)
{

   if (fled1->id != fled2->id)
      return(1);
   if (fled1->second != fled2->second)
      return(1);
   if (fled1->minute != fled2->minute)
      return(1);
   if (fled1->hour != fled2->hour)
      return(1);
   if (fled1->day != fled2->day)
      return(1);
   if (fled1->month != fled2->month)
      return(1);
   if (fled1->year != fled2->year)
      return(1);

   return(0);
}

/*

*/
int compare_event_time(struct fl_windows_event_id *fled1, int year, int month, int day, int hour, int minute, int second)
{
   int ret_val = 0;
   if (fled1->second != second)
      ret_val = 1;
   if (fled1->minute != minute)
      ret_val = 1;;
   if (fled1->hour != hour)
     ret_val = 1;
   if (fled1->day != day)
      ret_val = 1;
   if (fled1->month != month)
      ret_val = 1;
   if (fled1->year != year)
      ret_val = 1;

   if (ret_val == 1)
   {
      fled1->second = second;
      fled1->minute = minute;
      fled1->hour = hour;
      fled1->day = day;
      fled1->month = month;
      fled1->year = year;
   }

   return(ret_val);
}
