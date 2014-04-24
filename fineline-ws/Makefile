# FineLine-ws - Windows Search Database Parser
# Derek Chadwick 20/03/2014
# Builds Linux version of fineline-ws.

CC=gcc
CFLAGS=-c -Wall -ansi
LDFLAGS=-static
LIBS=-lesedb
SOURCES=fineline-ws.c fllog.c flutil.c flsocket.c flsearchcacheparser.c fleventfile.c flfilehashmap.c flfilterhashmap.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=fineline-ws
INCPREFIX=../../libs/libevtx-20131211
INCLUDES=-I$(INCPREFIX)/common -I$(INCPREFIX)/libfdatetime -I$(INCPREFIX)/libcerror -I$(INCPREFIX)/libcstring -I../common

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -DLINUX_BUILD $< -o $@

strip:
	strip fineline-ws

clean:
	rm *.o fineline-ws


