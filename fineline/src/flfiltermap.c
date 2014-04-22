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
   Date  : 22/12/2013

   Purpose:  Loads in the filter list file, then for each event type defined in the filter list searches the 
             the windows event hashmap (flhashmap) and if found sets the filter flag for the event as defined
             by the filter list entry. This flag is then used for filtering events while processing input event logs. 
             The events of interest are mostly in the Security.evtx event log.

             Filter List Format: "Event-ID" "Filter-Flag"

             Event-ID = (the Windows Event ID)
             Filter-Flag = (0 - Do Not Filter; 1 - Filter Out)

             Special Event-ID = "0000" Means all other events not specified in the filter list).
             0000 0 (Do not filter all other event types).
             0000 1 (Filter out all other event types not specified in the filter list).

             Example: (To filter out all events except 4260, 7800 and 9001)

             4260 0
             7800 0
             9001 0
             0000 1

*/

#include <stdio.h>
#include <string.h>

#include "fineline.h"

struct fl_event_filter *filters = NULL; /* head of the hashmap, used in all the macro calls */


void add_filter(int event_id, struct fl_event_filter *flef)
{
    struct fl_event_filter *s;

    HASH_FIND_INT(filters, &event_id, s);  /* id already in the hash? */
    if (s == NULL) 
	 {
      HASH_ADD_INT(filters, event_id, flef);  /* id: name of key field */
    }

}

struct fl_event_filter *find_filter(int event_id) 
{
    struct fl_event_filter *s;

    HASH_FIND_INT(filters, &event_id, s);  /* s: output pointer */
    return s;
}


void set_filters() 
{
  struct fl_event_filter *current_filter, *tmp;
  struct fl_windows_event_id *flei;

  HASH_ITER(hh, filters, current_filter, tmp) 
  {
     flei = find_windows_event_id(current_filter->event_id);
     if (flei != NULL)
        flei->filter_out = current_filter->filter_out;
  }
}

/* 
   Function: load_event_filters
   Purpose : loads in the event filter list file and sets the filter flags
             in the windows event list hashmap. Note the event hashmap must be 
             loaded before the filter hashmap is loaded or nothing will be set.
*/
int load_event_filters(char *filter_filename)
{
	char instr[FL_MAX_INPUT_STR];
	FILE *filter_file;
   struct fl_event_filter *flef;
   char *token = NULL;
	int filter_counter = 0;
   char tmp_str[32];

   filter_file = fopen(filter_filename, "r");
   if (filter_file == NULL)
   {
       printf("load_event_filters() <ERROR>: could not open event file: %s\n", filter_filename);
		 return(-1);
   }

   memset(tmp_str, 0, 32); /* !!!CLEAR THE BUFFERS!!! */
   memset(instr, 0, FL_MAX_INPUT_STR);

	while (fgets(instr, FL_MAX_INPUT_STR, filter_file) != NULL)
	{
		int index;
      int event_id;
      int filter_val;

		flef = (struct fl_event_filter *)xcalloc(sizeof(struct fl_event_filter));

		index = strcspn(instr, " ");
		if ((index == 0) || (index > MAX_EVENT_ID_SIZE))
		{
			printf("load_event_filters() <ERROR> Invalid event filter list entry!\n");
            continue;
		}

		strncpy(tmp_str, instr, index+1);
      event_id = atoi(tmp_str);

		token = strchr(instr, ' ');
      if ((token == NULL) || (strlen(token) > 32))
      {
         printf("load_event_filters() <ERROR> Invalid event filter list entry!\n");
         continue;
      }
      token[strlen(token)-1] = 0; /* get rid of the newline */
		filter_val = atoi(token);
		
		if ((event_id == 0) && (filter_val == 1)) /* for all event types other than those specified in the filter list file */
      {
         set_all_event_filters(filter_val); /* event list filter flags are set to 0 on load, only reset all if filter value = 1 */ 
      }
      else /* for the event types specified in the filter list file */
      {
         flef->event_id = event_id;
         flef->filter_out = filter_val;
		   add_filter(event_id, flef);
      }

		filter_counter++;
      memset(tmp_str, 0, 32); /* !!!CLEAR THE BUFFERS!!! */
      memset(instr, 0, FL_MAX_INPUT_STR);
	}

   set_filters(); /* go through the filter list, lookup the windows event and if found set the filter value */

   printf("load_event_filters() <INFO> Loaded %d event filters.\n", filter_counter);

   fclose(filter_file);

	return(0);
}

