# OS Fingerprinter Makefile
#
# Build with: make
# Clean with: make clean

CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = 

# Directories
SRC_DIR = src
INC_DIR = include
BIN_DIR = bin

# Source files
SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/network.c \
       $(SRC_DIR)/db_parser.c \
       $(SRC_DIR)/matcher.c \
       $(SRC_DIR)/utils.c

# Output
TARGET = $(BIN_DIR)/os_fingerprint

# Build
all: $(BIN_DIR) $(TARGET)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -I$(INC_DIR) $(SRCS) -o $(TARGET) $(LDFLAGS) -lm

# Clean
clean:
	rm -rf $(BIN_DIR)

# Install (optional)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean install