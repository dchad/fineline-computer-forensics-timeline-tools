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
   fineline-sensor.c

   Title : Fineline NST Sensor
   Author: Derek Chadwick
   Date  : 06/07/2014

   Purpose: Fineline Sensor Main Function. Processes command line options
            and executes packet sniffer mode or Snort/Suricata log follower
            mode.

*/

#include "flcommon.h"
#include "fineline-sensor.h"



/* TODO: static unsigned int sensor_id = 0; */

int main(int argc, char *argv[])
{
   char FL_out_file[FL_PATH_MAX_LENGTH];
   char server_ip_address[FL_IP_ADDR_MAX];
   char filter_file[FL_PATH_MAX_LENGTH];
   char capture_device[FL_PATH_MAX_LENGTH];
   char bpf_string[FL_PATH_MAX_LENGTH];
   int mode;
   int res = open_log_file(argv[0]);

   if (res < 0)
   {
      printf("fineline-sensor.c main() <ERROR> Could not open log file.\n");
      exit(FILE_ERROR);
   }
   print_log_entry("fineline-sensor.c main() <INFO> Starting Fineline Sensor 1.0\n");

   mode = parse_command_line_args(argc, argv, capture_device, FL_out_file, server_ip_address, filter_file);
   if (mode > 0)
   {

      if (mode & FL_CAPTURE_INPUT)
      {
         if (mode & FL_FILTER_ON)
         {
            load_bpf_filters(filter_file, bpf_string);
         }
         else
         {
            /* Only do layer 3 and above and not destination Fineline GUI    */
            /* as we will be pushing events to the Fineline GUI which may    */
            /* may be running on the local machine.                          */
            if (mode & FL_GUI_OUT)
            {
               sprintf(bpf_string, "ip and not (host %s and port %s)", server_ip_address, GUI_SERVER_PORT_STRING);
            }
            else
            {
               strncpy(bpf_string, "ip", 2); /* Not sending to GUI, so just filter on layer 3 packets. */
            }
         }
         start_capture(capture_device, bpf_string, FL_out_file, server_ip_address, mode);
      }
      else if (mode & FL_UNIFIED2_INPUT)
      {
         /* TODO: tail suricata logs (popen("tail")) */
         printf("TODO: Unified2 log monitoring not implemented.\n");
      }
      else
      {
         print_log_entry("fineline-sensor.c main() <ERROR> Invalid command line options - no capture mode specified!\n");
         show_sensor_help();
      }
   }
   else
   {
      print_log_entry("fineline-sensor.c main() <ERROR> Invalid command line options!\n");
      show_sensor_help();
   }

   close_log_file();

   exit(0);
}

/*
   Function: parse_command_line_args
   Purpose : Validates command line arguments.
   Input   : argc, argv, capture interface, server ip and filter file strings.
   Return  : returns -1 on error, mode of operation on success.
*/
int parse_command_line_args(int argc, char *argv[], char *capture_device, char *event_filename, char *server_ip_address, char *filter_file)
{
   int retval = 0;
   char timestr[100];
   int tlen;

   tlen = get_time_string(timestr, 99);

   memset(capture_device, 0, FL_PATH_MAX_LENGTH);
   memset(event_filename, 0, FL_PATH_MAX_LENGTH);
   memset(server_ip_address, 0, FL_PATH_MAX_LENGTH);
   memset(filter_file, 0, FL_PATH_MAX_LENGTH);
   strncpy(event_filename, EVENT_FILE, strlen(EVENT_FILE)); /* the default event file name */
   strncpy(capture_device, "eth0", 4);
   strncpy(server_ip_address, "127.0.0.1", 9); /* Default server on the local machine */

   if (tlen > 0) /* Build the default event filename, fineline-events-YYYYMMDD-HHMMSS.fle */
   {
      strncat(event_filename, timestr, tlen);
   }
   else
   {
      print_log_entry("parse_command_line_args() <WARNING> Invalid time string.\n");
   }
   strncat(event_filename, EVENT_FILE_EXT, 4);

   if (argc < 2)
   {
	   print_log_entry("parse_command_line_args(): invalid arguments < 2\n");
      return(-1);
   }
   else
   {
      int i;
      for (i = 1; i < argc; i++)
      {
         if (strncmp(argv[i], "-c", 2) == 0)
         {
            retval = retval | FL_CAPTURE_INPUT; /* Capture packets on a network interface */
         }
         if (strncmp(argv[i], "-t", 2) == 0)
         {
            retval = retval | FL_UNIFIED2_INPUT; /* Tail Unified2 log files */
         }
         else if (strncmp(argv[i], "-w", 2) == 0)
         {
            retval = retval | FL_FILE_OUT; /* Create FineLine event file */
         }
         else if (strncmp(argv[i], "-g", 2) == 0)
         {
            retval = retval | FL_GUI_OUT; /* Send event records to Fineline server */
         }
         else if (strncmp(argv[i], "-b", 2) == 0)
         {
            retval = retval | FL_FILE_OUT | FL_GUI_OUT; /* Create FineLine event file and send events to server */
         }
         else if (strncmp(argv[i], "-o", 2) == 0)
         {
            /* Optional FineLine event file name to use for output of event records */
            if ((i+1) < argc)
            {
               printf("parse_command_line_args() <INFO> FineLine event file: %s\n", argv[i+1]);
               strncpy(event_filename, argv[i+1], strlen(argv[i+1]));
            }
            else
            {
               print_log_entry("parse_command_line_args() <ERROR> Missing event file name.\n");
               return(-1);
            }
         }
         else if (strncmp(argv[i], "-i", 2) == 0)
         {
            /* Network interface for packet capture */
            if ((i+1) < argc)
            {
               printf("parse_command_line_args() <INFO> Network interface: %s\n", argv[i+1]);
               strncpy(capture_device, argv[i+1], strlen(argv[i+1]));
            }
            else
            {
               print_log_entry("parse_command_line_args() <ERROR> Missing network interface.\n");
               return(-1);
            }
         }
		   else if (strncmp(argv[i], "-a", 2) == 0)
		   {
			   if ((i+1) < argc)
			   {
			      /* IP address of the Fineline NST Server. */
			      printf("parse_command_line_args() <INFO> Server IP address: %s\n", argv[i+1]);
               strncpy(server_ip_address, argv[i+1], strlen(argv[i+1]));
			      if (validate_ipv4_address(server_ip_address) < 0)
			      {
				      print_log_entry("parse_command_line_args() <ERROR> Invalid Ifl4 address.\n");
                  return(-1);
			      }
			   }
			   else
			   {
			      print_log_entry("parse_command_line_args() <ERROR> Missing Ifl4 address.\n");
               return(-1);
			   }
		   }
         else if (strncmp(argv[i], "-f", 2) == 0)
         {
            /* Filter file name  */
            if ((i+1) < argc)
            {
               printf("parse_command_line_args() <INFO> Filter file: %s\n", argv[i+1]);
               strncpy(filter_file, argv[i+1], strlen(argv[i+1]));
			      retval = retval | FL_FILTER_ON;
            }
            else
            {
               print_log_entry("parse_command_line_args() <ERROR> Missing filter file name.\n");
               return(-1);
            }
         }
      }
   }

   print_log_entry("parse_command_line_args() <INFO> Finished processing command line arguments.\n");

   return(retval);
}

/* help */
int show_sensor_help()
{
   printf("\nFineline Sensor 1.0\n\n");
   printf("Command: finelineal-sensor <options>\n\n");
   printf("Capture packets from an interface                 : -c\n");
   printf("Tail a Unified2 event log                         : -t\n");
   printf("Output to a fineline event file                   : -w\n");
   printf("Send events to server                             : -s\n");
   printf("Specify fineline output filename                  : -o FILENAME\n");
   printf("Specify network interface                         : -i INTERFACE\n");
   printf("Specify a server IP address                       : -a 192.168.1.10\n");
   printf("Specify filter file                               : -f FILENAME\n");
   printf("\n");
   printf("Input and output files are optional. For sending events to the server\n");
   printf("-a <IPaddress> is mandatory. Minimal command line is:\n\n");
   printf("sudo finelineal-sensor -w -i wlan0\n\n");
   printf("This will capture packets on the wlan0 interface and output events into\n");
   printf("a default fineline event file: fineline-events-YYYYMMDD-HHMMSS.fle\n");
   printf("An optional BPF filter list can be included, the default filter\n");
   printf("file is fl-filter-list.txt\n");

   return(0);
}

