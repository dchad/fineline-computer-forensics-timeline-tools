# FineLine-ie - Internet Explorer Cache File Parser
# Derek Chadwick 01/01/2014
# Builds Linux version of fineline-iepre10.

CC=gcc
CFLAGS=-c -Wall -ansi
LDFLAGS=-static
LIBS=-lmsiecf
SOURCES=fineline-iepre10.c fllog.c flutil.c flsocket.c flieindexparser.c fleventfile.c flurlhashmap.c flfiltermap.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=fineline-iepre10
INCPREFIX=../../libs/libmsiecf-20140131
INCLUDES=-I$(INCPREFIX)/common -I$(INCPREFIX)/libfdatetime -I$(INCPREFIX)/libcerror -I$(INCPREFIX)/libcstring -I../common

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -DLINUX_BUILD $< -o $@

strip:
	strip fineline-iepre10

clean:
	rm *.o fineline-iepre10


