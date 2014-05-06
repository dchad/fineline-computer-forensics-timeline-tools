

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
   Fineline_Util.h

   Title : FineLine Computer Forensics Timeline Constructor Utilities
   Author: Derek Chadwick
   Date  : 22/12/2013

   Purpose: Wrapper class for various standard C lib functions to
            make them safer.

*/


#ifndef FINELINE_UTIL_H
#define FINELINE_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

class Fineline_Util
{
   public:
      Fineline_Util();
      virtual ~Fineline_Util();

      void fatal(const char *str);
      void *xcalloc(size_t size);
      void *xmalloc(size_t size);
      void *xrealloc(void *ptr, size_t size);
      int xfree(char *buf, int len);
      int print_help();
      char* xitoa(int value, char* result, int len, int base);
      int get_time_string(char *tstr, int slen);
      int validate_ipv4_address(char *ipv4_addr);
      int validate_ipv6_address(char *ipv6_addr);
      char *ltrim(char *s);
      char *rtrim(char *s);
      char *trim(char *s);

   protected:
   private:
};

#endif // FINELINE_UTIL_H
