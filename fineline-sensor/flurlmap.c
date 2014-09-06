
/*  Copyright 2014 Derek Chadwick

    This file is part of the Fineline Computer Forensic Tools.

    Fineline is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Fineline is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Fineline.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
   flurlmap.c

   Title : Fineline NST Sensor URL Map
   Author: Derek Chadwick
   Date  : 06/07/2014

   Purpose: A hashmap wrapper for uthash, used to store URLs extracted from
            packet captures and various statistics for each URL.

*/

#include "flcommon.h"
#include "fineline-sensor.h"

fl_url_record_t *url_map = NULL; /* the hash map head record */

void add_url(fl_url_record_t *flurl)
{
    fl_url_record_t *s;

    HASH_FIND_STR(url_map, flurl->url_record_string , s);  /* id already in the hash? */
    if (s == NULL)
    {
      HASH_ADD_STR(url_map, url_record_string, flurl);  /* id: name of key field */
    }

}

fl_url_record_t *find_url(char *lookup_string)
{
    fl_url_record_t *s;

    HASH_FIND_STR(url_map, lookup_string, s);  /* s: output pointer */
    return s;
}

fl_url_record_t *get_first_url_record()
{
   return(url_map);
}

fl_url_record_t *get_last_url_record()
{
   fl_url_record_t *s = get_first_url_record();
   if (s != NULL)
      return((fl_url_record_t *)s->hh.prev);
   return(NULL);
}

void delete_url(fl_url_record_t *url_record)
{
    HASH_DEL(url_map, url_record);  /* event: pointer to deletee */
    free(url_record);
}

void delete_all_urls()
{
  fl_url_record_t *current_url, *tmp;

  HASH_ITER(hh, url_map, current_url, tmp)
  {
    HASH_DEL(url_map,current_url);  /* delete it (url_map advances to next) */
    free(current_url);              /* free it */
  }
}

void write_url_map(FILE *outfile)
{
    fl_url_record_t *s;

    for(s=url_map; s != NULL; s=(fl_url_record_t *)(s->hh.next))
    {
        fputs(s->url_record_string, outfile);
    }
}

void send_url_map()
{
    fl_url_record_t *s;

    for(s=url_map; s != NULL; s=(fl_url_record_t *)(s->hh.next))    {
        send_event(s->url_record_string);
    }
}

void print_url_map()
{
    fl_url_record_t *s;

    for(s=url_map; s != NULL; s=(fl_url_record_t *)(s->hh.next))
    {
        printf("URL: %s\n", s->url_record_string);
    }
}

