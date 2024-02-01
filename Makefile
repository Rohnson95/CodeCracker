PROG=main.exe
SOURCES=main.cpp passwordCracker.cpp
DEPS=
CC=g++
CFLAGS=-Wall  -std=c++20
DEBUG?=1

ifeq ($(DEBUG), 1)
	CFLAGS += -g
	OUTPUTDIR=bin/debug
	PROG=main_debug.exe
else
	CFLAGS += -g0 -O3
	OUTPUTDIR=bin/release
endif

OPENSSL_INCLUDE = -IC:/msys64/mingw64/include
OPENSSL_LIBS = -LC:/msys64/mingw64/lib -lssl -lcrypto

OBJS =  $(addprefix $(OUTPUTDIR)/,$(SOURCES:.cpp=.o))

$(PROG): $(OUTPUTDIR) $(OBJS) 
	$(CC) $(CFLAGS) $(OPENSSL_INCLUDE) -o $(PROG) $(OBJS) $(OPENSSL_LIBS)

$(OUTPUTDIR)/%.o: %.cpp $(DEPS)
	$(CC) $(CFLAGS) -o $@ -c $< 

clean:
	@del /q "$(OUTPUTDIR)" 
	@del /q $(PROG)

$(OUTPUTDIR):
	@mkdir "$(OUTPUTDIR)"

.PHONY: clean test