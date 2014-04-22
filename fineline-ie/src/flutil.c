
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
   flutil.c

   Title : FineLine Computer Forensics Timeline Constructor Utilities
   Author: Derek Chadwick
   Date  : 22/12/2013

   Purpose: Wrapper functions for various standard C lib functions to
            make them safer.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "fineline-ie.h"

/* Redefine malloc with a fatal exit. */
void *xmalloc (size_t size)
{
   register void *value = malloc (size);
   if (value == 0)
   {
      fatal("xmalloc() <FATAL> Virtual Memory Exhausted!!!");
   }
   return value;
}

/* Redefine calloc with a fatal exit. */
void *xcalloc (size_t size)
{
   register void *value = calloc (size, 1);
   if (value == 0)
   {
      fatal("xmalloc() <FATAL> Virtual Memory Exhausted!!!");
   }
   return value;
}

/* Redefine realloc with a fatal exit. */
void *xrealloc (void *ptr, size_t size)
{
   register void *value = realloc (ptr, size);
   if (value == 0)
   {
      fatal ("xmalloc() <FATAL> Virtual Memory Exhausted");
   }
   return value;
}

/* Redefine free with buffer zeroing. */
int xfree(char *buf, int len)
{
   memset(buf, 0, len);
   free(buf);
   return(0);
}

/* Bail Out */
int fatal(char *str)
{
   printf("%s\n", str);
   exit(1);
}

/* help */
int print_help()
{
   printf("\nFineLine Computer Forensics Timeline Constructor 1.0\n\n");
   printf("Command: fineline-ie <options>\n\n");
   printf("Output to a fineline event file                   : -w\n");
   printf("Only send events to GUI                           : -s\n");
   printf("Specify fineline output filename                  : -o FILENAME\n");
   printf("Specify IE cache input file                       : -i FILENAME\n");
   printf("Specify a GUI server IP address                   : -a 192.168.1.10\n");
   printf("Specify URL filtering and filter file             : -f FILENAME\n");
   printf("\n");
   printf("Input and output files are optional. For sending events to the GUI\n");
   printf("-a <IPaddress> is mandatory. Minimal command line is:\n\n");
   printf("C:\\fineline-ie -w -i index.dat\n\n");
   printf("This will open the index.dat file and parse the URLs into the\n");
   printf("default fineline event file: fineline-events-YYYYMMDD-HHMMSS.fle\n");
   printf("An optional URL filter list can be included, the default filter\n");
   printf("file is fl-url-filter-list.txt\n");

   return(0);
}

/**
 * Modified version of char* style "itoa" with buffer length check.
 * (Kernighan and Ritchie)
 */

char *xitoa(int value, char* result, int len, int base)
{
   char *ptr;
   char *ptr1;
   char tmp_char;
   int tmp_value;
   int i = 0;

   if ((base < 2) || (base > 36)) 
   { 
	  *result = '\0';
      return (result); 
   }

   ptr = result;
   ptr1 = result;

   do {
         tmp_value = value;
         value /= base;
         *ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz" [35 + (tmp_value - value * base)];
      i++;
   } while ((i < len) && value );

   if (tmp_value < 0) *ptr++ = '-';
   *ptr-- = '\0';
   while(ptr1 < ptr) {
      tmp_char = *ptr;
      *ptr--= *ptr1;
      *ptr1++ = tmp_char;
   }
   return result;
}


/*
   Function: get_time_string()

   Purpose : Gets current date and time in a string.
           :
   Input   : String for date and time.
   Output  : Formatted date and time string.
*/
int get_time_string(char *tstr, int slen)
{
   time_t curtime;
   struct tm *loctime;
   int len;

   if ((tstr == NULL) || (slen < 15))
   {
      print_log_entry("get_time_string() <ERROR> Invalid string or length.\n");
      return(0);
   }
   /* Get the current time. */
   
   curtime = time (NULL);
   loctime = localtime (&curtime);
   if ((len = strftime(tstr, slen - 1, "-%Y%m%d-%H%M%S", loctime)) < 1)
   {
      printf("get_time_string() <WARNING> Indeterminate time string: %s\n", tstr);
   }

   return(len);
}


int validate_ipv4_address(char *ipv4_addr)
{
	/* TODO: a regex would be nice = m/\d+\.\d+\.\d+\.\d+/ */
	return(0);
}

int validate_ipv6_address(char *ipv6_addr)
{
	/* TODO: definitely need a regex for this one */

	return(0);
}

char *ltrim(char *s)
{
    while(isspace(*s)) s++;
    return s;
}

char *rtrim(char *s)
{
    char* back = s + strlen(s);
    while(isspace(*--back));
    *(back+1) = '\0';
    return s;
}

char *trim(char *s)
{
    return rtrim(ltrim(s)); 
}
