# OS Fingerprinter Makefile
#
# Just run 'make' to build the project.
# Run 'make clean' to remove build files.

CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LIBS = -lm

SRC = src/main.c \
      src/network.c \
      src/db_parser.c \
      src/matcher.c \
      src/utils.c

TARGET = bin/os_fingerprint

all: bin $(TARGET)

bin:
	mkdir -p bin

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -Iinclude -o $@ $^ $(LIBS)

clean:
	rm -rf bin

.PHONY: all clean