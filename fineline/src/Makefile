# FineLine - Computer Forensics Timeline Constructor
# Derek Chadwick 22/12/2013
# Builds Linux version of fineline.

CC=gcc
CFLAGS=-c -Wall -ansi
LDFLAGS=-static
LIBS=-levt -levtx
SOURCES=fineline.c fllog.c flutil.c fleventparser.c fleventfile.c fleventhashmap.c flevt.c flevtx.c flfiltermap.c flwineventhashmap.c flsocket.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=fineline
INCPREFIX=../../libs/libevtx-20131211
INCLUDES=-I$(INCPREFIX)/common/ -I$(INCPREFIX)/libfdatetime/ -I$(INCPREFIX)/libcerror/ -I$(INCPREFIX)/libcstring/

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -DLINUX_BUILD $< -o $@

strip:
	strip fineline

clean: 
	rm *.o fineline


