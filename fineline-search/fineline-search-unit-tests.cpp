
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

#include "gtest/gtest.h"

using ::testing::InitGoogleTest;

//1. Test Series FINELINE SEARCH

#include "Fineline_UI.h"

TEST(FineLineSearchThreadTests, ThreadCounterCorrect)
{
	Fineline_Thread *flt = new Fineline_Thread();
	Fl_Browser *flb = new Fl_Browser(20, 20, 100, 100);

   ASSERT_TRUE(NULL != flt);
   ASSERT_TRUE(NULL != flb);

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

   delete flt;
   delete flb;
}


TEST(FineLineSearchUITests, UIValid)
{

   Fineline_UI *flui = new Fineline_UI();

   ASSERT_TRUE(NULL != flui);

   delete flui;
}


//2. Test Series fineline-ws

//3. Test Series fineline-ie

//4. Test Series fineline-iepre10

//5. Test Series fineline-vs



int main(int argc, char **argv)
{
  InitGoogleTest(&argc, argv);

  printf("Starting FineLine Unit Test Suite\n");

  return RUN_ALL_TESTS();
}
