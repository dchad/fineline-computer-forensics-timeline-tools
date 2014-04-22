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
   flfilehashmap.c

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 22/12/2013

   Purpose: Wrapper functions for uthash by Troy Hanson. Use to implement
            a hashmap of the file event records being created during processing
            of the Windows.edb files.

*/

#include <stdio.h>
#include <string.h>

#include "fineline-ws.h"

struct fl_file_record *file_map = NULL; /* the hash map head record */

void add_file_record(uint64_t file_id, struct fl_file_record *flf)
{
    struct fl_file_record *s;

    HASH_FIND(hh, file_map, &file_id, sizeof(uint64_t), s);  /* id already in the hash? */
    if (s == NULL)
    {
      HASH_ADD(hh, file_map, id, sizeof(uint64_t), flf);  /* id: name of key field */
    }

}

struct fl_file_record *find_file(uint64_t file_id)
{
    struct fl_file_record *s;

    HASH_FIND(hh, file_map, &file_id, sizeof(file_id), s);  /* s: output pointer */
    return s;
}

struct fl_file_record *get_first_file_record()
{
   struct fl_file_record *s;
   uint64_t lowest = get_first_record_number();
   HASH_FIND(hh, file_map, &lowest, sizeof(uint64_t), s);
   return(s);
}

struct fl_file_record *get_last_file_record()
{
   struct fl_file_record *s = get_first_file_record();
   if (s != NULL)
      return((struct fl_file_record *)s->hh.prev);
   return(NULL);
}

void delete_url(struct fl_file_record *flf)
{
    HASH_DEL(file_map, flf);  /* event: pointer to deletee */
    free(flf);
}

void delete_all()
{
  struct fl_file_record *current_file, *tmp;

  HASH_ITER(hh, file_map, current_file, tmp)
  {
    HASH_DEL(file_map,current_file);  /* delete it (file_map advances to next) */
    free(current_file);              /* free it */
  }
}

void write_file_map(FILE *outfile)
{
    struct fl_file_record *s;

    for(s=file_map; s != NULL; s=(struct fl_file_record *)(s->hh.next))
    {
        fputs(s->file_event_string, outfile);
    }
}

void write_file_map_in_time_sequence(FILE *outfile, int lowest)
{
    struct fl_file_record *s;
    struct fl_file_record *m;
    HASH_FIND(hh, file_map, &lowest, sizeof(int), m);  /* get the first rul record then start iterating over the map */
    if (m != NULL)
    {
       for(s=m; s != NULL; s=(struct fl_file_record *)(s->hh.next))
       {
           fputs(s->file_event_string, outfile);
       }
    }
    /* now finish of the rest of the event list from the start of the map */
    for(s=file_map; s != NULL; s=(struct fl_file_record *)(s->hh.next))    {
        if (s->id > lowest)
           fputs(s->file_event_string, outfile);
        else
           break;
    }
}

uint64_t get_first_record_number()
{
    struct fl_file_record *s;
    int lowest = file_map->id;
    for(s=file_map; s != NULL; s=(struct fl_file_record *)(s->hh.next))    {
        if (s->id < lowest)
           lowest = s->id;
    }
    return(lowest);
}

void send_file_map()
{
    struct fl_file_record *s;

    for(s=file_map; s != NULL; s=(struct fl_file_record *)(s->hh.next))    {
        send_event(s->file_event_string);
    }
}

void send_file_map_in_time_sequence(int lowest)
{
    struct fl_file_record *s;
    struct fl_file_record *m;
    HASH_FIND(hh, file_map, &lowest, sizeof(int), m);  /* get the first event record then start iterating over the map */
    if (m != NULL)
	 {
       for(s=m; s != NULL; s=(struct fl_file_record *)(s->hh.next))
	    {
           send_event(s->file_event_string);
       }
    }
    /* now finish of the rest of the event list from the start of the map */
    for(s=file_map; s != NULL; s=(struct fl_file_record *)(s->hh.next))
	 {
        if (s->id > lowest)
           send_event(s->file_event_string);
        else
           break;
    }
}

void print_file_map()
{
    struct fl_file_record *s;

    for(s=file_map; s != NULL; s=(struct fl_file_record *)(s->hh.next))
    {
        printf("Event ID %d : Description %s\n", s->id, s->file_event_string);
    }
}


int modification_time_sort(struct fl_file_record *a, struct fl_file_record *b)
{

    long tmp = a->modification_time - b->modification_time;
    /* printf("time_sort() <INFO> Diff = %e\n", tmp); */

    if (tmp < 0)
       return(-1);
    if (tmp > 0)
       return(1);

    return (0);
}

int creation_time_sort(struct fl_file_record *a, struct fl_file_record *b)
{

    long tmp = a->creation_time - b->creation_time;
    /* printf("time_sort() <INFO> Diff = %e\n", tmp); */

    if (tmp < 0)
       return(-1);
    if (tmp > 0)
       return(1);

    return (0);
}

int access_time_sort(struct fl_file_record *a, struct fl_file_record *b)
{

    long tmp = a->access_time - b->access_time;
    /* printf("time_sort() <INFO> Diff = %e\n", tmp); */

    if (tmp < 0)
       return(-1);
    if (tmp > 0)
       return(1);

    return (0);
}


int record_number_sort(struct fl_file_record *a, struct fl_file_record *b)
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
    HASH_SORT(file_map, access_time_sort);
}

void sort_by_record_number()
{
   HASH_SORT(file_map, record_number_sort);
}
