
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
   Fineline_File_Project_Dialog.cpp

   Title : FineLine Computer Forensics Image Search GUI
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: FineLine FLTK GUI project dialog class implementation.

   Notes: EXPERIMENTAL

*/


#include "Fineline_Project_Dialog.h"

Fineline_Project_Dialog::Fineline_Project_Dialog(int x, int y, int w, int h, Fineline_Project *proj) : Fl_Double_Window(x, y, w, h, "Fineline Project Dialog")
{
   //ctor
   begin();

   Fl_Group* dialog_group = new Fl_Group(5, 5, w - 5, h - 5);
   dialog_group->tooltip("Click the save button to save the case/project properties.");

   project_name_field = new Fl_Input(100, 20, w - 120, 30, "Case Name:");
   project_investigator_field = new Fl_Input(100, 60, w - 120, 30, "Investigator:");
   project_summary_field = new Fl_Input(100, 100, w - 120, 30, "Summary:");
   project_start_date_field = new Fl_Input(100, 140, w - 120, 30, "Start Date:");
   project_end_date_field = new Fl_Input(100, 180, w - 120, 30, "End Date:");
   project_description_field = new Fl_Text_Editor(100, 245, w - 120, 250, "Description:");
   project_description_field->align(FL_ALIGN_LEFT_TOP); //FL_ALIGN_TOP_LEFT);
   textbuf = new Fl_Text_Buffer(FL_MAX_INPUT_STR);
   project_description_field->buffer(textbuf);
   textbuf->text();
   {
	   Fl_Button* o = new Fl_Button(w - 230, h - 45, 100, 30, "Save");
      o->callback((Fl_Callback*)button_callback, (void *)this);
      o->tooltip("Add the events to the timeline graph.");
   } // Fl_Button* o
   {
      Fl_Button* o = new Fl_Button(w - 120, h - 45, 100, 30, "Close");
      o->callback((Fl_Callback*)button_callback, (void *)this);
      o->tooltip("Close dialog without saving.");
   } // Fl_Button* o

   dialog_group->end();
   Fl_Group::current()->resizable(dialog_group);

   end();

   project_file = proj;
}

Fineline_Project_Dialog::~Fineline_Project_Dialog()
{
   //dtor
}

void Fineline_Project_Dialog::button_callback(Fl_Button *b, void *p)
{
   //TODO: get the calling button label and execute the required action
   Fineline_Project_Dialog *pd = (Fineline_Project_Dialog*)p;

   if (strncmp(b->label(), "Save", 4) == 0)
   {
      pd->project_file->setProjectName(pd->project_name_field->value());
      pd->project_file->setProjectInvestigator(pd->project_investigator_field->value());
      pd->project_file->setProjectStartDate(pd->project_start_date_field->value());
      pd->project_file->setProjectEndDate(pd->project_end_date_field->value());
      pd->project_file->setProjectSummary(pd->project_summary_field->value());
      pd->project_file->setProjectDescription(pd->textbuf->text());
   }
   pd->hide();
}

void Fineline_Project_Dialog::clear_fields()
{
   //TODO: empty of the text fields for a new project.
   project_name_field->value("");
   project_investigator_field->value("");
   project_summary_field->value("");
   project_start_date_field->value("");
   project_end_date_field->value("");
   textbuf->select(0, textbuf->length());
   textbuf->remove_selection();

   return;
}

void Fineline_Project_Dialog::show_dialog(bool new_project)
{
   //TODO: empty of the text fields for a new project.
   if (new_project)
   {
      clear_fields();
   }
   else
   {
      //TODO: populate the dialog fields from the project file object.
      project_name_field->value(project_file->getProjectName().c_str());
      project_investigator_field->value(project_file->getProjectInvestigator().c_str());
      project_summary_field->value(project_file->getProjectSummary().c_str());
      project_start_date_field->value(project_file->getProjectStartDate().c_str());
      project_end_date_field->value(project_file->getProjectEndDate().c_str());
      textbuf->text(project_file->getProjectDescription().c_str());
   }
   show();

   return;
}


