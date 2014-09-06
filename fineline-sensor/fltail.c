
/*  Copyright 2014 Derek Chadwick

    This file is part of the Fineline Network Security Tools.

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
   fltail.c

   Title : Fineline NST Sensor Tail IDS Logs
   Author: Derek Chadwick
   Date  : 06/07/2014

   Purpose: Fineline Sensor functions for tailing IDS logs. Options are
            fast.log, http.log and unified2.alert.xxx. Uses popen to
            create a pipe to the Linux tail command then enters a loop
            to read from the pipe, format the log entries as Fineline
            events then send the events to the Fineline Server or writes
            them to a Fineline event file.

            Example:

            sprintf(command_string, "tail -f %s\n", suricata-unified2-latest-logfilename);
            FILE *tail_pipe = popen(command_string, "r");

   Status:  EXPERIMENTAL
*/



#include "flcommon.h"
#include "fineline-sensor.h"

FILE *tail_pipe;

/*
   Function: open_tail_pipe
   Purpose : Opens the specified log file.
   Input   : Log file name.
   Output  : Returns -1 on error, 0 on success.
*/
int open_tail_pipe(char *log_file_name)
{
   tail_pipe = NULL;

   return(0);
}

/*
   Function: start_tail
   Purpose : First determine which log file to open, fast.log, http.log or unified2
             Then call open_tail_pipe(), if open is OK then call follow_tail().
   Input   : Log file and output options.
   Output  : Returns -1 on error, 0 on success.
*/
int start_tail(int fineline_options, int log_option)
{

   return(0);
}

/*
   Function: follow_tail
   Purpose : Implements a loop for reading then output from the tail command.
   Input   : Output options.
   Output  : Returns -1 on error, 0 on success.
*/
int follow_tail()
{

   return(0);
}
