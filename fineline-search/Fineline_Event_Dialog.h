#ifndef FINELINE_EVENT_DIALOG_H
#define FINELINE_EVENT_DIALOG_H

#include <FL/Fl.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Browser.H>
#include <FL/Fl_Box.H>
#include <FL/filename.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Native_File_Chooser.H>

#include "fineline-search.h"

class Fineline_Event_Dialog : public Fl_Double_Window
{
   public:
      Fineline_Event_Dialog(int x, int y, int w, int h);
      virtual ~Fineline_Event_Dialog();

      static void button_callback(Fl_Button *b, void *p);

      static void put_file_metadata(fl_file_record_t *flrec);

      //TODO: need a pointer to the timeline graph

   protected:
   private:
};

#endif // FINELINE_EVENT_DIALOG_H
