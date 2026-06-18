CC      = gcc
CFLAGS  = -std=gnu99 -Wall -Wextra
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
