# This file is part of dfuzzer.
#
# Author: Matus Marhefka  2013
#

CC=gcc
CFLAGS=-Wall -w `pkg-config --cflags --libs gio-2.0 libffi` #-DDEBUG -g
OBJ=dfuzzer.o introspection.o fuzz.o rand.o
TARGET=dfuzzer
all: dfuzzer
.PHONY: doc clean


makefile.dep:
	$(CC) -MM *.c >makefile.dep
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET)

doc:
	doxygen doxyfile

clean:
	rm -f $(TARGET) $(OBJ) makefile.dep

-include makefile.dep
