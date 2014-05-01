
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
   fineline-search-unit-tests.cpp

   Title : FineLine Computer Forensics Unit Tests
   Author: Derek Chadwick
   Date  : 02/04/2014

   Purpose: Implements unit test suite using GoogleTest C++ Testing Framework

   Notes: EXPERIMENTAL

*/


#include <stdio.h>
#include <stdlib.h>
#include <string>

#include "gtest/gtest.h"

using ::testing::InitGoogleTest;
using namespace std;

//1. Test Series FINELINE SEARCH

#include "Fineline_UI.h"
#include "Fineline_Filter_List.h"
#include "Fineline_Log.h"
#include "Fineline_Event_List.h"
#include "Fineline_File_System.h"


TEST(FineLineSearchThreadTests, ValidateMethods)
{
   Fineline_Log *flg = new Fineline_Log();
	Fineline_Thread *flt = new Fineline_Thread(flg);
	Fl_Browser *flb = new Fl_Browser(20, 20, 100, 100);

   ASSERT_TRUE(NULL != flt);
   ASSERT_TRUE(NULL != flb);
   ASSERT_TRUE(NULL != flg);

	EXPECT_EQ(0, flt->get_active_threads());
	EXPECT_EQ(0, flt->get_running());

	flt->start_task(flb);

	EXPECT_EQ(1, flt->get_active_threads());
	EXPECT_EQ(1, flt->get_running());

	flt->start_task(flb);

	EXPECT_EQ(2, flt->get_active_threads());
	EXPECT_EQ(1, flt->get_running());

	flt->start_task(flb);

	EXPECT_EQ(3, flt->get_active_threads());
   EXPECT_EQ(1, flt->get_running());

   flt->stop_task();

 	EXPECT_EQ(0, flt->get_active_threads());
	EXPECT_EQ(0, flt->get_running());

   delete flt;
   delete flb;
}


TEST(FineLineSearchUITests, ValidUI)
{

   Fineline_UI *flui = new Fineline_UI();

   ASSERT_TRUE(NULL != flui);

   delete flui;
}


TEST(FineLineSearchFilterTests, ValidateMethods)
{
   string filter_file("fl-file-filter-list-example.txt");
   string filter_file_bad("bad_file.txt");
   Fineline_Filter_List *flist = new Fineline_Filter_List();

   ASSERT_TRUE(NULL != flist);

   EXPECT_EQ(-1, flist->load_filter_file());
   EXPECT_EQ(-1, flist->load_filter_file(filter_file_bad));
   EXPECT_EQ(0, flist->load_filter_file(filter_file));
   EXPECT_EQ(0, flist->match_filename("inbox.eml"));
   EXPECT_GE(flist->match_filename("C:\\temp\\mypasswords.doc"), 0);
   EXPECT_GE(flist->match_filename("randomstuff.pdf"), 0);
   EXPECT_EQ(-1, flist->match_filename("randomstuff.bin"));

   delete flist;
}


TEST(FineLineSearchLogTests, ValidateMethods)
{

   Fineline_Log *flog = new Fineline_Log();

   ASSERT_TRUE(NULL != flog);

   EXPECT_EQ(0, flog->open_log_file());
   EXPECT_EQ(0, flog->print_log_entry("Unit Test.\n"));

   delete flog;
}


TEST(FineLineSearchEventListTests, ValidateMethods)
{

   Fineline_Event_List *flist = new Fineline_Event_List();
   fl_file_record_t * flf = (fl_file_record_t *) xmalloc(sizeof(fl_file_record_t));
   string filename;
   char num[256];
   int i;

   ASSERT_TRUE(NULL != flist);
   ASSERT_TRUE(NULL != flf);

   EXPECT_EQ(0, flist->list_size());
   EXPECT_EQ(1, flist->add_file_record(flf));

   for (i = 0; i < 100000; i++)
   {
      flf = (fl_file_record_t *) xmalloc(sizeof(fl_file_record_t));
      ASSERT_TRUE(NULL != flf);
      filename = "C:\\temp\\file";
      filename.append(xitoa(i, num, 256, 10));
      filename.append(".doc");
      flist->add_file_record(flf);
   }

   EXPECT_EQ(100001, flist->list_size());
   EXPECT_EQ(0, flist->clear_list());
   delete flist;
   //xfree((char *) flf, sizeof(fl_file_record_t));
}

TEST(FineLineSearchFileSystemProcessingTests, ValidateMethods)
{
   Fineline_Log *flog = new Fineline_Log();
   Fl_Browser *flb = new Fl_Browser(20, 20, 100, 100);
   string test_image_1 = "test-image-1.dd";
   string test_image_2 = "test-image-2.ewf";
   string test_image_3 = "test-image-3.aff";
   string bad_image = "bad-image.dd";
   Fineline_File_System *ffs = new Fineline_File_System(flb, bad_image, flog);

   ASSERT_TRUE(NULL != ffs);

   flog->open_log_file();

   EXPECT_EQ(-1, ffs->open_forensic_image());

   delete ffs;
   ffs = new Fineline_File_System(flb, test_image_1, flog);

   EXPECT_EQ(0, ffs->open_forensic_image());
   EXPECT_EQ(0, ffs->process_forensic_image());
   EXPECT_EQ(0, ffs->close_forensic_image());

   delete ffs;
   ffs = new Fineline_File_System(flb, test_image_2, flog);

   EXPECT_EQ(0, ffs->open_forensic_image());
   EXPECT_EQ(0, ffs->process_forensic_image());
   EXPECT_EQ(0, ffs->close_forensic_image());

   delete ffs;
   ffs = new Fineline_File_System(flb, test_image_3, flog);

   EXPECT_EQ(0, ffs->open_forensic_image());
   EXPECT_EQ(0, ffs->process_forensic_image());
   EXPECT_EQ(0, ffs->close_forensic_image());

   flog->close_log_file();

   delete ffs;
   delete flb;
   delete flog;
}

int main(int argc, char **argv)
{
  InitGoogleTest(&argc, argv);

  printf("Starting FineLine Unit Test Suite\n");

  return RUN_ALL_TESTS();
}
