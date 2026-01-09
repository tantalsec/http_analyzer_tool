CC = gcc
CFLAGS = -Wall -Wextra -O2
INCLUDES = -I/usr/include/tantal
TARGET = hatt
SOURCE = hatt.c
LDLIBS = -ltantal

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SOURCE) $(LDLIBS)

clean:
	rm -f $(TARGET) *.o

rebuild: clean all

.PHONY: all clean rebuild
