# Compiler settings - Can be customized
CC = gcc
# Compiler flags:
# -Iinclude: Look for header files in the 'include' directory
# -Wall: Enable all standard warnings
# -g: Add debugging information (useful for gdb)
CFLAGS = -Iinclude -Wall -g

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Find all .c files in src directory
SRCS = $(wildcard $(SRC_DIR)/*.c)
# Convert .c filenames to .o filenames inside obj directory
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# The final executable name
TARGET = $(BIN_DIR)/fingerprinter

# Default target (what runs when you type 'make')
all: directories $(TARGET)

# Link all object files to create the executable
$(TARGET): $(OBJS)
	@echo "Linking..."
	$(CC) $(CFLAGS) -o $@ $^
	@echo "Build successful! Run with: sudo ./$(TARGET)"

# Compile source files into object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Create necessary directories if they don't exist
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)

# Clean up build files
clean:
	@echo "Cleaning up..."
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean directories