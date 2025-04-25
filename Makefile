# Compiler to use
CC = gcc

# Executable name
EXEC = dump_memory

# Source file
SRC = main.c

# Compiler flags
# Grouping warnings, optimization, standard, and sanitizer
CFLAGS = -Wall \
         -Wextra \
         -Wfloat-equal \
         -Wundef \
         -Wshadow \
         -Wpointer-arith \
         -Wcast-align \
         -Wstrict-prototypes \
         -Wstrict-overflow=5 \
         -Wwrite-strings \
         -Wcast-qual \
         -Wswitch-default \
         -Wswitch-enum \
         -Wconversion \
         -Wunreachable-code \
         -Wformat=2 \
         -O3 \
         -std=c17 \
         -fsanitize=undefined

# Default target: build the executable
all: $(EXEC)

# Rule to link the executable
$(EXEC): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(EXEC)
	@echo "Successfully built $(EXEC)"

# Rule to clean up built files
clean:
	@echo "Cleaning up..."
	rm -f $(EXEC)

# Phony targets (targets that don't represent actual files)
.PHONY: all clean
