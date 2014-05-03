# FineLine - Computer Forensics Timeline Constructor
# Derek Chadwick 15/04/2014
# Builds Linux version of fineline-search and unit tests.

CC=g++
CFLAGS=-c -Wall -ansi
LDFLAGS=

# Library Dependencies

TESTLDDIRS=-L../../libs/gtest-1.7.0/lib/.libs
LIBS=-lfltk -lXext -lX11 -lm -lpthread -ltsk -lewf -lafflib
TESTLIBS=-lgtest

# Source files

SOURCES=Fineline_UI.cpp  \
Fineline_Thread_FLTK.cpp \
Fineline_Thread_ACE.cpp  \
Fineline_Filter_Map.cpp  \
Fineline_Event_Map.cpp   \
Fineline_Log.cpp         \
Fineline_Socket_BSD.cpp  \
Fineline_Socket_ACE.cpp  \
Fineline_Filter_List.cpp \
Fineline_Event_List.cpp  \
Fineline_File_System.cpp \
../common/flutil.cpp
MAINSOURCES=fineline-search.cpp $(SOURCES)
TESTSOURCES=fineline-search-unit-tests.cpp $(SOURCES)

# Object files

OBJECTS=$(MAINSOURCES:.cpp=.o)
TESTOBJECTS=$(TESTSOURCES:.cpp=.o)

# Executable files

EXECUTABLE=fineline-search
TESTEXECUTABLE=fineline-search-unit-tests

# Include directories

INCPREFIX=../../libs
INCLUDES=-I$(INCPREFIX)/ACE_wrappers/ace -I../common
TESTINCLUDES=-I$(INCPREFIX)/gtest-1.7.0/include

# Target rules

all: $(SOURCES) $(EXECUTABLE) $(TESTSOURCES) $(TESTEXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

$(TESTEXECUTABLE): $(TESTOBJECTS)
	$(CC) $(LDFLAGS) $(TESTLDDIRS) $(TESTOBJECTS) $(LIBS) $(TESTLIBS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $(INCLUDES) $(TESTINCLUDES) -DLINUX_BUILD -DHAVE_PTHREAD_H $< -o $@

strip:
	strip fineline-search

clean:
	rm *.o *.log fineline-search fineline-search-unit-tests

tests: $(TESTSOURCES) $(TESTEXECUTABLE)

