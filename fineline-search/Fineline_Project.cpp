

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
   Fineline_Project.cpp

   Title : FineLine Computer Forensics Image Searcher GUI
   Author: Derek Chadwick
   Date  : 12/06/2014

   Purpose: Fineline project properties and file I/O.

   Notes: EXPERIMENTAL

*/

#include <stdio.h>
#include <stdlib.h>

#include <FL/fl_ask.H>

#include "Fineline_Project.h"
#include "Fineline_Log.h"

Fineline_Project::Fineline_Project()
{
   //ctor
   project_file = NULL;
   modified = false;

}

Fineline_Project::~Fineline_Project()
{
   //dtor
}

int Fineline_Project::new_project(const char *filename)
{
	project_file = fopen(filename, "w+");

	if (project_file == NULL)
	{
	   string msg = "open_project() <ERROR>: Could not open project file: ";
	   msg.append(filename);
	   Fineline_Log::print_log_entry(msg.c_str());
	   // move to UI class -> fl_message(msg.c_str());
      return(-1);
	}
	project_file_name = filename;
	modified = false;

   return(0);

}

int Fineline_Project::open_project(const char *filename)
{

	project_file = fopen(filename, "r+");

	if (project_file == NULL)
	{
	   string msg = "open_project() <ERROR>: Could not open project file: ";
	   msg.append(filename);
	   Fineline_Log::print_log_entry(msg.c_str());
	   // move to UI class -> fl_message(msg.c_str());
      return(-1);
	}
	project_file_name = filename;
	modified = false;
   read_project_header();
   read_file_metadata_list();  // TODO: pass in the metadata list.
   read_file_system_tree();    // TODO: pass in the file system tree.
   read_statistical_records(); // TODO: pass in the statistical data.
   read_timeline_event_list(); // TODO: pass in the timeline event list.

   return(0);
}

int Fineline_Project::save_project()
{
   if (project_file == NULL)
   {
      return(-1);
   }
   write_project_header();
   //TODO: write the marked file metadata, file system tree, event timeline and project report.
   write_file_metadata_list();  // TODO: pass in the metadata list.
   write_file_system_tree();    // TODO: pass in the file system tree.
   write_statistical_records(); // TODO: pass in the statistical data.
   write_timeline_event_list(); // TODO: pass in the timeline event list.

   return(0);
}

int Fineline_Project::save_project_as(const char *filename)
{
   return(0);
}

int Fineline_Project::close_project()
{
   if (project_file != NULL)
      fclose(project_file);

   modified = false;
   project_file = NULL;

   return(0);
}

bool Fineline_Project::project_modified()
{
   return(modified);
}

/*
   Function: write_project_header()

   Purpose : Creates a project header string and writes to the project file.
           :
   Input   : Project properties.
   Output  : Timestamped project header entry.
*/
int Fineline_Project::write_project_header()
{
   time_t curtime;
   struct tm *loctime;
   string hdr;
   char *time_str;

   /* Get the current time. */
   curtime = time (NULL);
   loctime = localtime (&curtime);
   time_str = asctime(loctime);


   hdr = "<project><name>";
   hdr.append(project_name);
   hdr.append("</name><investigator>");
   hdr.append(project_investigator);
   hdr.append("</investigator><summary>");
   hdr.append(project_summary);
   hdr.append("</summary><startdate>");
   hdr.append(project_start_date);
   hdr.append("</startdate><enddate>");
   hdr.append(project_end_date);
   hdr.append("</enddate><description>");
   hdr.append(project_description);
   hdr.append("</description><projecttime>");
   hdr.append(time_str);
   hdr.append("</projecttime></project>\n");
   fputs (hdr.c_str(), project_file);

   Fineline_Log::print_log_entry("write_fineline_project_header() <INFO> Wrote Project Header.\n");

   return(0);
}

int Fineline_Project::write_file_metadata_list()  // TODO: pass in the metadata list.
{
   return(0);
}

int Fineline_Project::write_file_system_tree()    // TODO: pass in the file system tree.
{
   return(0);
}

int Fineline_Project::write_statistical_records() // TODO: pass in the statistical data.
{
   return(0);
}

int Fineline_Project::write_timeline_event_list() // TODO: pass in the timeline event list.
{
   return(0);
}


int Fineline_Project::read_project_header()
{
   return(0);
}

int Fineline_Project::read_file_metadata_list()  // TODO: pass in the metadata list.
{
   return(0);
}

int Fineline_Project::read_file_system_tree()    // TODO: pass in the file system tree.
{
   return(0);
}

int Fineline_Project::read_statistical_records() // TODO: pass in the statistical data.
{
   return(0);
}

int Fineline_Project::read_timeline_event_list() // TODO: pass in the timeline event list.
{
   return(0);
}

/*
    Getter/Setter methods
*/
string Fineline_Project::getProjectName()
{
   return(project_name);
}
 string Fineline_Project::getProjectFileName()
{
   return(project_file_name);
}
string Fineline_Project::getProjectInvestigator()
{
   return(project_investigator);
}
string Fineline_Project::getProjectSummary()
{
   return(project_summary);
}
string Fineline_Project::getProjectDescription()
{
   return(project_description);
}
string Fineline_Project::getProjectStartDate()
{
   return(project_start_date);
}
string Fineline_Project::getProjectEndDate()
{
   return(project_end_date);
}
void Fineline_Project::setProjectName(string pn)
{
   project_name = pn;
   modified = true;
}
void Fineline_Project::setProjectFileName(string pfn)
{
   project_file_name = pfn;
   modified = true;
}
void Fineline_Project::setProjectInvestigator(string pi)
{
   project_investigator = pi;
   modified = true;
}
void Fineline_Project::setProjectSummary(string ps)
{
   project_summary = ps;
   modified = true;
}
void Fineline_Project::setProjectDescription(string pd)
{
   project_description = pd;
   modified = true;
}
void Fineline_Project::setProjectStartDate(string sd)
{
   project_start_date = sd;
   modified = true;
}
void Fineline_Project::setProjectEndDate(string ed)
{
   project_end_date = ed;
   modified = true;
}
