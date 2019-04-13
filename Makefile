PROGS = oppctl
CLEANFILES = $(PROGS)*.o $(PROGS)
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wextra
NSRC := ../netmap
CFLAGS += -I sys -I$(NSRC)/sys
UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
	LDFLAGS += -lbsd
endif

all: $(PROGS)
oppctl: oppctl.c
	$(CC) $(CFLAGS) -o oppctl oppctl.c $(LDFLAGS)
clean:
	-@rm -rf $(CLEANFILES)
