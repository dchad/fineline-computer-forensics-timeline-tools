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
   flurlhashmap.c

   Title : FineLine Computer Forensics Timeline Constructor
   Author: Derek Chadwick
   Date  : 22/12/2013

   Purpose: Wrapper functions for uthash by Troy Hanson. Use to implement
            a hashmap of the URLs being created during processing
            of the WebCacheV01.dat files.

*/

#include <stdio.h>
#include <string.h>

#include "fineline-ie.h"

struct fl_url_record *url_map = NULL; /* the hash map head record */

void add_url_record(uint64_t url_id, struct fl_url_record *flurl)
{
    struct fl_url_record *s;

    HASH_FIND(hh, url_map, &url_id, sizeof(uint64_t), s);  /* id already in the hash? */
    if (s == NULL)
    {
      HASH_ADD(hh, url_map, id, sizeof(uint64_t), flurl);  /* id: name of key field */
    }

}

struct fl_url_record *find_url(uint64_t url_id)
{
    struct fl_url_record *s;

    HASH_FIND(hh, url_map, &url_id, sizeof(url_id), s);  /* s: output pointer */
    return s;
}

struct fl_url_record *get_first_url_record()
{
   struct fl_url_record *s;
   uint64_t lowest = get_first_record_number();
   HASH_FIND(hh, url_map, &lowest, sizeof(uint64_t), s);
   return(s);
}

struct fl_url_record *get_last_url_record()
{
   struct fl_url_record *s = get_first_url_record();
   if (s != NULL)
      return((struct fl_url_record *)s->hh.prev);
   return(NULL);
}

void delete_url(struct fl_url_record *url_record)
{
    HASH_DEL(url_map, url_record);  /* event: pointer to deletee */
    free(url_record);
}

void delete_all()
{
  struct fl_url_record *current_url, *tmp;

  HASH_ITER(hh, url_map, current_url, tmp)
  {
    HASH_DEL(url_map,current_url);  /* delete it (url_map advances to next) */
    free(current_url);              /* free it */
  }
}

void write_url_map(FILE *outfile)
{
    struct fl_url_record *s;

    for(s=url_map; s != NULL; s=(struct fl_url_record *)(s->hh.next))
    {
        fputs(s->url_record_string, outfile);
    }
}

void write_url_map_in_time_sequence(FILE *outfile, uint64_t lowest)
{
    struct fl_url_record *s;
    struct fl_url_record *m;
    HASH_FIND(hh, url_map, &lowest, sizeof(uint64_t), m);  /* get the first rul record then start iterating over the map */
    if (m != NULL)
    {
       for(s=m; s != NULL; s=(struct fl_url_record *)(s->hh.next))
       {
           fputs(s->url_record_string, outfile);
       }
    }
    /* now finish of the rest of the event list from the start of the map */
    for(s=url_map; s != NULL; s=(struct fl_url_record *)(s->hh.next))    {
        if (s->id > lowest)
           fputs(s->url_record_string, outfile);
        else
           break;
    }
}

uint64_t get_first_record_number()
{
    struct fl_url_record *s;
    uint64_t lowest = url_map->id;
    for(s=url_map; s != NULL; s=(struct fl_url_record *)(s->hh.next))    {
        if (s->id < lowest)
           lowest = s->id;
    }
    return(lowest);
}

void send_url_map()
{
    struct fl_url_record *s;

    for(s=url_map; s != NULL; s=(struct fl_url_record *)(s->hh.next))    {
        send_event(s->url_record_string);
    }
}

void send_url_map_in_time_sequence(uint64_t lowest)
{
    struct fl_url_record *s;
    struct fl_url_record *m;
    HASH_FIND(hh, url_map, &lowest, sizeof(uint64_t), m);  /* get the first event record then start iterating over the map */
    if (m != NULL)
	 {
       for(s=m; s != NULL; s=(struct fl_url_record *)(s->hh.next))
	    {
           send_event(s->url_record_string);
       }
    }
    /* now finish of the rest of the event list from the start of the map */
    for(s=url_map; s != NULL; s=(struct fl_url_record *)(s->hh.next))
	 {
        if (s->id > lowest)
           send_event(s->url_record_string);
        else
           break;
    }
}

void print_url_map()
{
    struct fl_url_record *s;

    for(s=url_map; s != NULL; s=(struct fl_url_record *)(s->hh.next))
    {
        printf("Event ID %ld : Description %s\n", (long)s->id, s->url_record_string);
    }
}


int time_sort(struct fl_url_record *a, struct fl_url_record *b)
{
    /*
    int aby = a->year - b->year;
    int abm = a->month - b->month;
    int abd = a->day - b->day;

    if (aby < 0)
       return(-1);
    else if (aby > 0)
       return(1);

    if (abm < 0)
       return(-1);
    else if (abm > 0)
       return(1);

    if (abd < 0)
       return(-1);
    else if (abd > 0)
       return(1);
 */

    double tmp = a->url_time - b->url_time;
    /* printf("time_sort() <INFO> Diff = %e\n", tmp); */

    if (tmp < 0)
       return(-1);
    if (tmp > 0)
       return(1);

    return (0);
}

int record_number_sort(struct fl_url_record *a, struct fl_url_record *b)
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
    HASH_SORT(url_map, time_sort);
}

void sort_by_record_number()
{
   HASH_SORT(url_map, record_number_sort);
}
