
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
   Fineline_Thread_FLTK.cpp

   Title : FineLine Computer Forensics Image Searcher FLTK Thread Class (posix threads)
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine FLTK based thread class definition implements a wrapper
            class for posix or Win32 threads in an FLTK GUI.

   Notes: EXPERIMENTAL

*/


#include <iostream>

#include "Fineline_Thread_FLTK.h"
#include "../common/threads.h"

using namespace std;

#ifdef LINUX_BUILD
#include <unistd.h>
#define FINELINE_SLEEP(delay) usleep(delay*1000);
#else
#define FINELINE_SLEEP(delay) Sleep(delay);
#endif

static int running = 0;
static long active_threads = 0;
static Fineline_Log *flog;

Fineline_Thread::Fineline_Thread(Fineline_Log *log)
{
   flog = log;
   running = 0;
}

Fineline_Thread::~Fineline_Thread()
{
   running = 0;
}

/*
   Function: thread_task
   Purpose : Worker function for the posix/win32 thread,
             must be a C function. Implements a server
             task to read Fineline events from TCP/UDP
             socket port 58989.
   Input   : Pointer to the thread id (integer/long).
   Output  : Adds events to the GUI event browser.
*/
void* thread_task(void* p)
{
   Fl_Browser *event_browser = (Fl_Browser *)p;
   long id = active_threads;
   long update_num = 0;
   char msg[256];

   flog->print_log_entry("Start thread %ld\n", id);

   while(running)
   {

#ifdef LINUX_BUILD
      usleep(5000); //Linux 5 milliseconds
#else
      Sleep(500);     //Wndows half a second
#endif

	   update_num++;
	   sprintf(msg, "Thread #%ld Update %ld\n", id, update_num);
      cout << msg;
     //flog->print_log_entry(msg);

      Fl::lock();

      //do some GUI updates here...
	   if (event_browser != NULL)
	   {
	      event_browser->add(msg);
	      Fl::awake(event_browser); //TODO: is this necessary?
      }


      Fl::unlock();

   }
   return 0;
}

void Fineline_Thread::start_task(Fl_Browser *flb)
{
	cout << "Fineline_Thread_FLTK::start_task() <INFO> Starting thread." << endl;
	running = 1;
	Fl_Thread thread_id;
	active_threads++;
	fl_create_thread(thread_id, thread_task, (void *)flb);
}

void Fineline_Thread::stop_task()
{
	running = 0;
	active_threads = 0;
}

long Fineline_Thread::get_active_threads()
{
	return(active_threads);
}

int Fineline_Thread::get_running()
{
	return(running);
}
