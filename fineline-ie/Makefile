# FineLine-ie - Internet Explorer Cache File Parser
# Derek Chadwick 22/12/2013
# Builds Linux version of fineline-ie.

CC=gcc
CFLAGS=-c -Wall -ansi
LDFLAGS=-static
LIBS=-lesedb
SOURCES=fineline-ie.c fllog.c flutil.c flsocket.c fliecacheparser.c fleventfile.c flurlhashmap.c flfilterhashmap.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=fineline-ie
INCPREFIX=../../libs/libevtx-20131211
INCLUDES=-I$(INCPREFIX)/common -I$(INCPREFIX)/libfdatetime -I$(INCPREFIX)/libcerror -I$(INCPREFIX)/libcstring -I../common

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -DLINUX_BUILD $< -o $@

strip:
	strip fineline-ie

clean:
	rm *.o fineline-ie


