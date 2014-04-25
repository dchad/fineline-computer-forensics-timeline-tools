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
   Fineline_Thread_FLTK.h

   Title : FineLine Computer Forensics Image Searcher FLTK Thread Class (posix threads)
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine FLTK based thread class definition implements a wrapper
            class for posix or Win32 threads in an FLTK GUI.

   Notes: EXPERIMENTAL

*/

#include <stdio.h>
#include <FL/Fl.H>
#include <FL/Fl_Browser.H>


class Fineline_Thread
{
private:

public:

	Fineline_Thread();
	~Fineline_Thread();

	void start_task(Fl_Browser *flb);
	void stop_task();
	long get_active_threads();
	int get_running();
};
