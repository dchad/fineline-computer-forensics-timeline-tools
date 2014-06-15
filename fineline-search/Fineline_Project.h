
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
   Fineline_Project.h

   Title : FineLine Computer Forensics Image Searcher GUI
   Author: Derek Chadwick
   Date  : 12/06/2014

   Purpose: Fineline project properties and file I/O.
            A project file consists of the following sections:
               1. Project Header.
               2. Metadata of marked files.
               3. Filesystem tree.
               4. Timeline event list.
               5. Statistical analysis records.

   Notes: EXPERIMENTAL

*/


#ifndef FINELINE_PROJECT_H
#define FINELINE_PROJECT_H


#include <string>
#include <regex>

#include "fineline-search.h"

using namespace std;

class Fineline_Project
{
   public:

      Fineline_Project();
      virtual ~Fineline_Project();

      int new_project(const char *filename);
      int open_project(const char *filename);
      int save_project();
      int save_project_as(const char *filename);
      int close_project();
      bool project_modified();

      int write_project_header();
      int write_file_metadata_list();  // TODO: pass in the metadata list.
      int write_file_system_tree();    // TODO: pass in the file system tree.
      int write_statistical_records(); // TODO: pass in the statistical data.
      int write_timeline_event_list(); // TODO: pass in the timeline event list.

      int read_project_header();
      int read_file_metadata_list();  // TODO: pass in the metadata list.
      int read_file_system_tree();    // TODO: pass in the file system tree.
      int read_statistical_records(); // TODO: pass in the statistical data.
      int read_timeline_event_list(); // TODO: pass in the timeline event list.

      //Getter/Setter methods
      string getProjectName();
      string getProjectFileName();
      string getProjectInvestigator();
      string getProjectSummary();
      string getProjectDescription();
      string getProjectStartDate();
      string getProjectEndDate();
      void setProjectName(string pn);
      void setProjectFileName(string pfn);
      void setProjectInvestigator(string pi);
      void setProjectSummary(string ps);
      void setProjectDescription(string pd);
      void setProjectStartDate(string sd);
      void setProjectEndDate(string ed);

   protected:
   private:

      FILE *project_file;
      string project_file_name;
      string project_name;
      string project_investigator;
      string project_start_date;
      string project_end_date;
      string project_description;
      string project_summary;
      bool modified;

};

#endif // FINELINE_PROJECT_H
