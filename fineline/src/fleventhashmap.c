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
   fleventhashmap.c

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 22/12/2013

   Purpose: Wrapper functions for uthash by Troy Hanson. Use to implement
            a hashmap of the FineLine events being created during processing
            of the windows event files. A hashmap is necessary to sort the
            event records into time order sequence. The records in the 
            Windows event files are not in time order because the files are
            implemented as circular buffers with a fixed maximum size. So the
            beginning of a Windows event file will normally have event records
            that are later in time order than the events near the end of the
            log file.

*/

#include <stdio.h>
#include <string.h>

#include "fineline.h"

struct fl_event_record *event_map = NULL; /* the hash map head record */

void add_event_record(uint64_t event_id, struct fl_event_record *fler)
{
    struct fl_event_record *s;

    HASH_FIND(hh, event_map, &event_id, sizeof(uint64_t), s);  /* id already in the hash? */
    if (s == NULL) 
	 {
      HASH_ADD(hh, event_map, id, sizeof(uint64_t), fler );  /* id: name of key field */
    }

}

struct fl_event_record *find_event(uint64_t event_id) 
{
    struct fl_event_record *s;

    HASH_FIND(hh, event_map, &event_id, sizeof(event_id), s);  /* s: output pointer */
    return s;
}

struct fl_event_record *get_first_event_record()
{
   struct fl_event_record *s;
   uint64_t lowest = get_first_record_number();
   HASH_FIND(hh, event_map, &lowest, sizeof(uint64_t), s); 
   return(s);
}

struct fl_event_record *get_last_event_record()
{
   struct fl_event_record *s = get_first_event_record();
   if (s != NULL)
      return((struct fl_event_record *)s->hh.prev);
   return(NULL);
}

void delete_event(struct fl_event_record *event_record) 
{
    HASH_DEL(event_map, event_record);  /* event: pointer to deletee */
    free(event_record);
}

void delete_all() 
{
  struct fl_event_record *current_event, *tmp;

  HASH_ITER(hh, event_map, current_event, tmp) 
  {
    HASH_DEL(event_map,current_event);  /* delete it (event_map advances to next) */
    free(current_event);            /* free it */
  }
}

void write_event_map(FILE *outfile) 
{
    struct fl_event_record *s;

    for(s=event_map; s != NULL; s=(struct fl_event_record *)(s->hh.next)) 
    {
        fputs(s->event_record_string, outfile);
    }
}

void write_event_map_in_time_sequence(FILE *outfile, uint64_t lowest)
{
    struct fl_event_record *s;
    struct fl_event_record *m;    
    HASH_FIND(hh, event_map, &lowest, sizeof(uint64_t), m);  /* get the first event record then start iterating over the map */
    if (m != NULL) 
    {
       for(s=m; s != NULL; s=(struct fl_event_record *)(s->hh.next)) 
       {
           fputs(s->event_record_string, outfile);
       }
    }
    /* now finish of the rest of the event list from the start of the map */
    for(s=event_map; s != NULL; s=(struct fl_event_record *)(s->hh.next))     {
        if (s->id > lowest)
           fputs(s->event_record_string, outfile);
        else
           break;
    }
}

uint64_t get_first_record_number()
{
    struct fl_event_record *s;
    uint64_t lowest = event_map->id;
    for(s=event_map; s != NULL; s=(struct fl_event_record *)(s->hh.next))     {
        if (s->id < lowest)
           lowest = s->id;
    }
    return(lowest);
}

void send_event_map() 
{
    struct fl_event_record *s;

    for(s=event_map; s != NULL; s=(struct fl_event_record *)(s->hh.next)) 
    {
        send_event(s->event_record_string);
    }
}

void send_event_map_in_time_sequence(uint64_t lowest)
{
    struct fl_event_record *s;
    struct fl_event_record *m;    
    HASH_FIND(hh, event_map, &lowest, sizeof(uint64_t), m);  /* get the first event record then start iterating over the map */
    if (m != NULL) 
    {
       for(s=m; s != NULL; s=(struct fl_event_record *)(s->hh.next)) 
       {
           send_event(s->event_record_string);
       }
    }
    /* now finish of the rest of the event list from the start of the map */
    for(s=event_map; s != NULL; s=(struct fl_event_record *)(s->hh.next)) 
    {
        if (s->id > lowest)
           send_event(s->event_record_string);
        else
           break;
    }
}

void print_event_map() 
{
    struct fl_event_record *s;

    for(s=event_map; s != NULL; s=(struct fl_event_record *)(s->hh.next)) 
    {
        printf("Event ID %ld : Description %s\n", (long)s->id, s->event_record_string);
    }
}


int time_sort(struct fl_event_record *a, struct fl_event_record *b) 
{
   /* windows 64bit times are doubles representing fractional days from epoch time (1900)? */
    double tmp = a->event_time - b->event_time; 
    if (tmp < 0)
       return(-1);
    if (tmp > 0)
       return(1);
    return (0);
}

int record_number_sort(struct fl_event_record *a, struct fl_event_record *b) 
{
    uint64_t tmp = a->id - b->id;
    if (tmp < 0)
       return(-1);
    if (tmp > 0)
       return(1);
    return (0);
}

void sort_by_time() 
{
    HASH_SORT(event_map, time_sort);
}

void sort_by_record_number()
{
   HASH_SORT(event_map, record_number_sort);
}
