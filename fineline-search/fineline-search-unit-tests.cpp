
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
#include "Fineline_File_System_Tree.h"
#include "Fineline_Util.h"
#include "Fineline_Progress_Dialog.h"


TEST(FineLineSearchThreadTests, ValidateMethods)
{
   Fineline_Log *flog = new Fineline_Log();
	Fineline_Thread *flt = new Fineline_Thread(flog);
	Fl_Browser *flb = new Fl_Browser(20, 20, 100, 100);

   ASSERT_TRUE(NULL != flt);
   ASSERT_TRUE(NULL != flb);
   ASSERT_TRUE(NULL != flog);

   EXPECT_EQ(0, flog->open_log_file());

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

   //EXPECT_EQ(0, flog->close_log_file());

   //delete flt; NOTE: will cause a segfault because threads have not exited yet.
   //delete flb;
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
   EXPECT_EQ(0, flog->close_log_file());

   delete flog;
}


TEST(FineLineSearchEventListTests, ValidateMethods)
{
   Fineline_Util flut;
   Fineline_Event_List *flist = new Fineline_Event_List();
   fl_file_record_t * flf = (fl_file_record_t *) flut.xmalloc(sizeof(fl_file_record_t));
   string filename;
   char num[256];
   int i;

   ASSERT_TRUE(NULL != flist);
   ASSERT_TRUE(NULL != flf);

   EXPECT_EQ(0, flist->list_size());
   EXPECT_EQ(1, flist->add_file_record(flf));

   for (i = 0; i < 100000; i++)
   {
      flf = (fl_file_record_t *) flut.xmalloc(sizeof(fl_file_record_t));
      ASSERT_TRUE(NULL != flf);
      filename = "C:\\temp\\file";
      filename.append(flut.xitoa(i, num, 256, 10));
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
   Fineline_Progress_Dialog *fpd = new Fineline_Progress_Dialog(20, 20, 600, 600);
   Fineline_File_System_Tree *fltree = new Fineline_File_System_Tree(20, 20, 100, 100);
   string test_image_1 = "../../testing/ext3-img-kw-1.dd";
   string test_image_2 = "../../testing/8-jpeg-search.dd";
   string test_image_3 = "../../testing/ext-part-test-2.dd";
   string bad_image = "bad-image.dd";
   Fineline_File_System *ffs = new Fineline_File_System(fltree, bad_image, fpd, flog);

   ASSERT_TRUE(NULL != ffs);
   ASSERT_TRUE(NULL != fltree);
   ASSERT_TRUE(NULL != flog);

   flog->open_log_file();

   EXPECT_EQ(-1, ffs->open_forensic_image());

   delete ffs;
   ffs = new Fineline_File_System(fltree, test_image_1, fpd, flog);

   EXPECT_EQ(0, ffs->open_forensic_image());
   EXPECT_EQ(0, ffs->process_forensic_image());
   EXPECT_EQ(0, ffs->close_forensic_image());

   delete ffs;
   ffs = new Fineline_File_System(fltree, test_image_2, fpd, flog);

   EXPECT_EQ(0, ffs->open_forensic_image());
   EXPECT_EQ(0, ffs->process_forensic_image());
   EXPECT_EQ(0, ffs->close_forensic_image());

   delete ffs;
   ffs = new Fineline_File_System(fltree, test_image_3, fpd, flog);

   EXPECT_EQ(0, ffs->open_forensic_image());
   EXPECT_EQ(0, ffs->process_forensic_image());
   EXPECT_EQ(0, ffs->close_forensic_image());

   flog->close_log_file();

   delete ffs;
   delete fltree;
   delete flog;
}


TEST(FineLineSearchFileSystemTreeTests, ValidateMethods)
{
   Fineline_Util flut;
   Fineline_File_System_Tree *ftree = new Fineline_File_System_Tree(20, 100, 800, 600);
   fl_file_record_t * flf = (fl_file_record_t *) flut.xmalloc(sizeof(fl_file_record_t));
   string filename;
   char num[256];
   int i;

   ASSERT_TRUE(NULL != ftree);
   ASSERT_TRUE(NULL != flf);

   EXPECT_EQ(0, ftree->tree_size());

   for (i = 0; i < 1000; i++)
   {
      flf = (fl_file_record_t *) flut.xmalloc(sizeof(fl_file_record_t));
      ASSERT_TRUE(NULL != flf);
      filename = "C:\\temp\\file";
      filename.append(flut.xitoa(i, num, 256, 10));
      filename.append(".doc");
      ftree->add_file(filename, flf);
   }
   for (i = 0; i < 1000; i++)
   {
      flf = (fl_file_record_t *) flut.xmalloc(sizeof(fl_file_record_t));
      ASSERT_TRUE(NULL != flf);
      filename = "C:\\Windows\\file";
      filename.append(flut.xitoa(i, num, 256, 10));
      filename.append(".exe");
      ftree->add_file(filename, flf);
   }
      for (i = 0; i < 1000; i++)
   {
      flf = (fl_file_record_t *) flut.xmalloc(sizeof(fl_file_record_t));
      ASSERT_TRUE(NULL != flf);
      filename = "C:\\Users\\admin\\file";
      filename.append(flut.xitoa(i, num, 256, 10));
      filename.append(".txt");
      ftree->add_file(filename, flf);
   }
      for (i = 0; i < 1000; i++)
   {
      flf = (fl_file_record_t *) flut.xmalloc(sizeof(fl_file_record_t));
      ASSERT_TRUE(NULL != flf);
      filename = "/etc/file";
      filename.append(flut.xitoa(i, num, 256, 10));
      filename.append(".bin");
      ftree->add_file(filename, flf);
   }
   EXPECT_EQ(4000, ftree->tree_size());
   EXPECT_EQ(0, ftree->clear_tree());

   delete ftree;
}

int main(int argc, char **argv)
{
  InitGoogleTest(&argc, argv);

  printf("Starting FineLine Unit Test Suite\n");

  return RUN_ALL_TESTS();
}
