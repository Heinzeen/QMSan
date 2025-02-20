LIBFILE = msan-giovese.a

CC = gcc
CFLAGS = -ggdb

CFILES = msan-giovese.c
HEADERS = msan-giovese.h

objects = $(CFILES:.c=.o)

all: lib

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

lib: $(objects)
	$(AR) -crs $(LIBFILE) $(objects)

$(objects): $(HEADERS)

clean:
	rm -fr $(objects) $(LIBFILE)
