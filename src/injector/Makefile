CC       = gcc
CFLAGS   = -Wall -Wextra -g -O0

.PHONY: all clean

all: injector

# --- Injector (ptrace-based .so injection into running process) ---

injector: injector.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

clean:
	rm -f injector