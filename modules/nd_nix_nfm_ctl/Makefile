

CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lm


SOURCES = nd_nix_nfm_ctl.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = nd_nix_nfm_ctl
INSTALL_DIR = ../../build

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJECTS): $(SOURCES)
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	@if [ ! -d $(INSTALL_DIR) ]; then \
		echo "Creating $(INSTALL_DIR) directory"; \
		mkdir -p $(INSTALL_DIR); \
	fi
	install $(TARGET) $(INSTALL_DIR)

clean:
	rm -f $(OBJECTS) $(TARGET)



