CC      = gcc
# -O2 matters here: the build was previously unoptimized, which made the
# 600k-iteration key derivation ~5x slower than it needs to be.
CFLAGS  = -std=gnu99 -O2 -Wall -Wextra
TARGET  = vault
OBJS    = aes.o passHash.o vault.o main.o

# Default target: built when you just type `make`
all: $(TARGET)

# Link step: combine all object files into the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Compile step: each .o depends on its .c (and the headers).
# The pattern rule "%.o: %.c" means "to make any X.o, compile X.c"
%.o: %.c aes.h passHash.h vault.h
	$(CC) $(CFLAGS) -c $< -o $@

# Remove build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

# Install to a directory on your PATH
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean install
