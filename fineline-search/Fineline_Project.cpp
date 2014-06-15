

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
#include <iostream>

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
	project_file = fopen(filename, "w");

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

   close_project();

   return(0);

}

int Fineline_Project::open_project(const char *filename)
{

	project_file = fopen(filename, "r");

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

   close_project();

   return(0);
}

int Fineline_Project::save_project()
{
   project_file = fopen(project_file_name.c_str(), "r+");

   if (project_file == NULL)
   {
	   string msg = "save_project() <ERROR>: Could not open project file: ";
	   msg.append(project_file_name);
	   Fineline_Log::print_log_entry(msg.c_str());
      return(-1);
   }

   write_project_header();
   //TODO: write the marked file metadata, file system tree, event timeline and project report.
   write_file_metadata_list();  // TODO: pass in the metadata list.
   write_file_system_tree();    // TODO: pass in the file system tree.
   write_statistical_records(); // TODO: pass in the statistical data.
   write_timeline_event_list(); // TODO: pass in the timeline event list.

   close_project();

   return(0);
}

int Fineline_Project::save_project_as(const char *filename)
{
   project_file_name = filename;
   project_file = fopen(filename, "w");

   if (project_file == NULL)
   {
	   string msg = "save_project_as() <ERROR>: Could not create project file: ";
	   msg.append(project_file_name);
	   Fineline_Log::print_log_entry(msg.c_str());
      return(-1);
   }

   write_project_header();
   //TODO: write the marked file metadata, file system tree, event timeline and project report.
   write_file_metadata_list();  // TODO: pass in the metadata list.
   write_file_system_tree();    // TODO: pass in the file system tree.
   write_statistical_records(); // TODO: pass in the statistical data.
   write_timeline_event_list(); // TODO: pass in the timeline event list.

   close_project();

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
           : Uses the following schema to serialize the project properties:
           : <project><name></name><investigator></investigator><summary></summary><startdate></startdate>
           : <enddate></enddate><description></description></project>
   Input   : Project properties.
   Output  : Timestamped project header line.
*/
int Fineline_Project::write_project_header()
{
   time_t curtime;
   struct tm *loctime;
   string hdr, tmp_str;
   char *time_str;
   unsigned int i;

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

   // Remove any new lines from the description so the project header is all on one line.

   for (i = 0; i < project_description.size(); i++)
   {
      if ((project_description[i] != '\n') && (project_description[i] != '\r'))
      {
         tmp_str.append(1, project_description[i]);
      }
      else
      {
         tmp_str.append("<nl>");
      }
   }

   hdr.append(tmp_str);
   hdr.append("</description><projecttime>");
   hdr.append(Fineline_Util::rtrim(time_str)); //remove the newline at the end of the time string
   hdr.append("</projecttime></project>\n");

   if (fputs (hdr.c_str(), project_file) == EOF)
   {
      string msg = "write_project_header() <ERROR>: Could not write project header: ";
	   msg.append(project_file_name);
	   Fineline_Log::print_log_entry(msg.c_str());
      return(-1);
   }

   Fineline_Log::print_log_entry("write_project_header() <INFO> Wrote Project Header.\n");

   return(0);
}

int Fineline_Project::write_file_metadata_list()  // TODO: pass in the metadata list.
{
   // The file metadata items are serialised using the following schema:
   // <filemetadatalist><metadata><filepath></filepath><modtime></modtime><acctime></acctime><cretime></cretime>
   // <owner></owner><filesize></filesize></metadata></filemetadatalist>
   return(0);
}

int Fineline_Project::write_file_system_tree()    // TODO: pass in the file system tree.
{
   // The file system tree is serialised using the following schema:
   // <filesystemtree><node><filepath></filepath><marked></marked></node></filesystemtree>

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

/*
   Function: read_project_header()

   Purpose : Reads in the first line of the project file and parses the
           : project properties using regexes.
           : Uses the following schema to deserialize the project properties:
           : <project><name></name><investigator></investigator><summary></summary><startdate></startdate>
           : <enddate></enddate><description></description></project>
   Input   : Project header line from project file.
   Output  : Project properties.
*/
int Fineline_Project::read_project_header()
{
   char in_str[FL_MAX_INPUT_STR];

   if (fgets(in_str, FL_MAX_INPUT_STR, project_file) == NULL)
   {
      string msg = "read_project_header() <ERROR>: Could not read project file: ";
	   msg.append(project_file_name);
	   Fineline_Log::print_log_entry(msg.c_str());
      return(-1);
   }

   /*
      Implementation Note:
      If compiling with gcc beware the bizarre regex fiasco in gcc versions prior to 4.9,
      <regex> was not fully implemented in older gcc versions so regex code could be
      compiled but it would not work correctly and produced random errors/program aborts.
      Nobody ever bothered to explain this situation, hence the large number of
      questions on stackoverflow asking why regex code was not working.
   */

   regex pn_regex("<name>(.+)</name>");
   regex pi_regex("<investigator>(.+)</investigator>");
   regex ps_regex("<summary>(.+)</summary>");
   regex psd_regex("<startdate>(.+)</startdate>");
   regex ped_regex("<enddate>(.+)</enddate>");
   regex pd_regex("<description>(.+)</description>");

   string search_line = in_str;
   smatch search_result;

   //Fineline_Log::print_log_entry(search_line.c_str());
   //if (regex_match(search_line, search_result, pn_regex)) NOTE: regex_match does not work!!!
   //{
   //   Fineline_Log::print_log_entry("Found a match.");
   //}
   //else
   //{
   //   Fineline_Log::print_log_entry("Match not Found!!!");
   //}
   regex_search(search_line, search_result, pn_regex); //search for project name
   if(search_result[1].str().size() > 0)               //ignore empty lines
   {
      project_name = search_result[1].str();
      Fineline_Log::print_log_entry(project_name.c_str());
   }

   regex_search(search_line, search_result, pi_regex);  //search for investigator name
   if(search_result[1].str().length() > 0)              //ignore empty lines
   {
      project_investigator = search_result[1].str();
   }

   regex_search(search_line, search_result, ps_regex);  //search for project summary
   if(search_result[1].str().length() > 0)              //ignore empty lines
   {
      project_summary = search_result[1].str();
   }

   regex_search(search_line, search_result, psd_regex);  //search for project start date
   if(search_result[1].str().length() > 0)              //ignore empty lines
   {
      project_start_date = search_result[1].str();
   }

   regex_search(search_line, search_result, ped_regex);  //search for project end date
   if(search_result[1].str().length() > 0)              //ignore empty lines
   {
      project_end_date = search_result[1].str();
   }

   regex_search(search_line, search_result, pd_regex);  //search for project description
   if(search_result[1].str().length() > 0)              //ignore empty lines
   {
      project_description = search_result[1].str();
      //TODO: replace any <nl> with newlines.
   }

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
