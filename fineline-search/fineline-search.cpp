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
   fineline-search.cpp

   Title : FineLine Computer Forensics Image Searcher
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine search main. Searches forensic images for evidence. Image types supported:
            Raw images (single/multi)
			EWF format
			AFF format

   Dependencies: FLTI GUI library, The Sleuth Kit (TSK) library, libewf, libaff.

*/

#include "Fineline_UI.h"

int main(int argc, char *argv[])
{

   Fineline_UI *flui = new Fineline_UI();

   flui->show(argc, argv);

   Fl::lock(); //enable multithreaded support by implementing locking on the main event thread.

   return Fl::run(); //start main event loop.
}

