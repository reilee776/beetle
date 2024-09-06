# Makefile for creating a shared library

# value define
CC = gcc
CFLAGS = -fPIC -Wall
LIB_NAME = libnd_nix_nfm_lib.so
SOURCE = nd_nix_nfm_lib.c
OBJECT = $(SOURCE:.c=.o)

# default
all: $(LIB_NAME)

# lib create
$(LIB_NAME): $(OBJECT)
	$(CC) -shared -o $@ $^

# object file create
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# cleanup
clean:
	rm -f $(OBJECT) $(LIB_NAME)

.PHONY: all clean

