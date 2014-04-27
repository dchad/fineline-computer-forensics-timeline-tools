#ifndef FINELINE_EVENT_LIST_H
#define FINELINE_EVENT_LIST_H

#include <vector>
#include <string>

#include "fineline-search.h"

using namespace std;

class Fineline_Event_List
{
   public:
      Fineline_Event_List();
      virtual ~Fineline_Event_List();

      int add_file_record(fl_file_record_t *flf);
      int delete_file_record(int record_index);
      int find_file_record(string filename);
      int sort_records();
      int write_records();
      int send_records();
      int list_size();


   protected:
   private:

   vector<fl_file_record_t *> file_list;

   //TODO: Fineline_Event_File fl_event_file; NO put in write_records();

};

#endif // FINELINE_EVENT_LIST_H
