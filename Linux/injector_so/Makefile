CC       = gcc
CXX      = g++
CFLAGS   = -Wall -Wextra -g -O0
CXXFLAGS = -Wall -Wextra -g -O0 -std=c++17
LDFLAGS  = -lpthread

.PHONY: all clean

all: librevokehook.so injector

# --- RevokeHook shared library (inject via LD_PRELOAD or dlopen) ---

librevokehook.so: revokehook.cpp sigbp.c sigbp.h
	$(CXX) $(CXXFLAGS) -shared -fPIC -o $@ revokehook.cpp sigbp.c $(LDFLAGS) -lcrypto

# --- Injector (ptrace-based .so injection into running process) ---

injector: injector.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

# --- Standalone breakpoint engine library ---

libsigbp.so: sigbp.c sigbp.h
	$(CC) $(CFLAGS) -shared -fPIC -o $@ sigbp.c $(LDFLAGS)

clean:
	rm -f *.o libsigbp.so librevokehook.so injector
