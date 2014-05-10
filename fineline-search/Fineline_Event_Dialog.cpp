#include "Fineline_Event_Dialog.h"

Fineline_Event_Dialog::Fineline_Event_Dialog(int x, int y, int w, int h) : Fl_Double_Window(x, y ,w, h, "Event Editor")
{
   Fl_Group* event_group = new Fl_Group(10, 30, w - 10, h - 50);
   event_group->tooltip("Edit the file metadata items and click the save button to add the event to the timeline graph.");
         {
			Fl_Button* o = new Fl_Button(20, 90, 100, 30, "Save");
            o->callback((Fl_Callback*)button_callback, (void *)this);
         }  // Fl_Button* o
         {
            Fl_Button* o = new Fl_Button(30, 200, 260, 30, "Cancel");
            o->callback((Fl_Callback*)button_callback, (void *)this);
         } // Fl_Button* o
   event_group->end();
   Fl_Group::current()->resizable(event_group);
}

Fineline_Event_Dialog::~Fineline_Event_Dialog()
{
   //dtor
}

void Fineline_Event_Dialog::put_file_metadata(fl_file_record_t *flrec)
{

}

void Fineline_Event_Dialog::button_callback(Fl_Button *b, void *p)
{
   ((Fineline_Event_Dialog *)p)->hide();
}
