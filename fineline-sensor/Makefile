# Fineline Computer Forensic Tools
# Derek Chadwick 06/07/2014
# Builds Linux version of Fineline Sensor.

# Compiler flags

CC=gcc
CFLAGS=-c -Wall -ansi -DLINUX_BUILD -D_GNU_SOURCE

# Linker flags

LDFLAGS=
LIBS=-lpcap
LIBDIRS=-L../../libs

# Sources

SOURCES=fineline-sensor.c \
flsniffer.c \
flfilter.c  \
flurlmap.c  \
flipmap.c   \
fltail.c    \
fleventfile.c \
../common/fllog.c \
../common/flutil.c \
../common/flsocket.c

# Objects

OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=fineline-sensor

# Includes

INCPREFIX=
INCLUDES=-I../common

# Target Rules

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

strip:
	strip fineline-sensor

clean:
	rm *.o *.log fineline-sensor ../common/*.o


