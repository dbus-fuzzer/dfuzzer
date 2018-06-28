#==============================================================================
# This file is part of dfuzzer.
# Copyright(C) 2014, 2015, Red Hat, Inc., Matus Marhefka <mmarhefk@redhat.com>
#==============================================================================

CC=gcc
CFLAGS=-Wall -w -O2 -D_FORTIFY_SOURCE=2 -fstack-protector --param=ssp-buffer-size=4 `pkg-config --cflags --libs gio-2.0 libffi` -g
OBJ=dfuzzer.o introspection.o fuzz.o rand.o
TARGET=dfuzzer
all: dfuzzer
.PHONY: doc man clean


makefile.dep:
	$(CC) -MM *.c >makefile.dep
$(TARGET): $(OBJ)
	$(CC) $(OBJ) $(CFLAGS) -o $(TARGET)

doc:
	doxygen doxyfile

# .gz should be copied into /usr/share/man/man1
man:
	gzip -c ../man/dfuzzer.1 > ../man/dfuzzer.1.gz

clean:
	rm -f $(TARGET) $(OBJ) makefile.dep ../man/dfuzzer.1.gz
	rm -rf ../doc

-include makefile.dep
