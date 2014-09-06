/*  Copyright 2014 Derek Chadwick

    This file is part of the Fineline Computer Forensics Tools.

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
   flfilter.c

   Title : Fineline Sensor BPF Filters
   Author: Derek Chadwick
   Date  : 22/12/2013

   Purpose:  Loads in the packet filter file. Filter files are plain text
             with each line contain a BSD Packet Filter (BPF) rule. These
             are the same syntax as used in Wireshark to specify capture
             filters. If multiple lines are read from the filter file they
             will be logical OR'ed to create a single packet filter rule
             for libpcap.

             Example:

             tcp port 80
             tcp port 22
             src ip 8.8.8.8
             icmp

             This is equivalent to:

             (tcp port 80) or (tcp port 22) or (src ip 8.8.8.8) or icmp

             This means capture http, ssh, icmp and all packets from the Google DNS server(8.8.8.8).
             All other traffic will be ignored.

             For more information see the Wireshark User Guide, TCPDUMP man pages or
             http://wiki.wireshark.org/CaptureFilters

*/

#include "flcommon.h"
#include "fineline-sensor.h"


/*
   Function: load_bpf_filters
   Purpose : loads in the filter list file and constructs a single
             filter string by OR'ing the text lines.
*/
int load_bpf_filters(char *filter_filename, char *filter_string)
{
	char instr[FL_MAX_INPUT_STR];
	char tmpstr[FL_MAX_INPUT_STR];
	FILE *filter_file;
	int filter_counter = 0;

   filter_file = fopen(filter_filename, "r");
   if (filter_file == NULL)
   {
      printf("load_bpf_filters() <ERROR>: could not open event file: %s\n", filter_filename);
      return(-1);
   }

   /* !!!CLEAR THE BUFFERS!!! */
   memset(instr, 0, FL_MAX_INPUT_STR);
   memset(tmpstr, 0, FL_MAX_INPUT_STR);

	while (fgets(instr, FL_MAX_INPUT_STR, filter_file) != NULL)
	{
      rtrim(instr); /* Remove any newlines/whitespace from end of line then surround with brackets. */
      sprintf(tmpstr, "(%s)", instr);
      if (filter_counter > 0)
      {
         strncat(filter_string, " or ", 4);
      }
      strncat(filter_string, tmpstr, strlen(instr));

		filter_counter++;

      /* !!!CLEAR THE BUFFERS!!! */
      memset(instr, 0, FL_MAX_INPUT_STR);
      memset(tmpstr, 0, FL_MAX_INPUT_STR);
	}

   printf("load_bpf_filters() <INFO> Loaded %d BPF filters.\n", filter_counter);

   fclose(filter_file);

	return(0);
}

