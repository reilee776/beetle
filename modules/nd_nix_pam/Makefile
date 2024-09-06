CC = gcc
CFLAGS = -fPIC
LDFLAGS = -shared -lcrypt

TARGET = nd_nix_pam.so

all: $(TARGET)

pam_module.o: nd_nix_pam.c
	$(CC) $(CFLAGS) -c nd_nix_pam.c

$(TARGET): nd_nix_pam.o
	$(CC) $(LDFLAGS) -o $(TARGET) nd_nix_pam.o

clean:
	rm -f nd_nix_pam.o $(TARGET)

.PHONY: all clean

