CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
TARGET   = test_starter
SRCS     = src/main.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
