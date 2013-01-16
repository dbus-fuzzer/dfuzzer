CC=gcc
CFLAGS=-Wall
GFLAGS=`pkg-config --cflags --libs glib-2.0`
DFLAGS=`pkg-config --cflags --libs dbus-1` `pkg-config --cflags --libs dbus-glib-1`

all: dbus_list

dbus: dbus_list.c
	$(CC) $(CFLAGS) $(GFLAGS) $(DFLAGS) -o dbus_list dbus_list.c

.PHONY: clean
clean:
	rm -f dbus_list
