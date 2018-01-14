CC = cc
CFLAGS  =
CINCLUDES =
COMPILE  = $(CC) $(CFLAGS) $(CINCLUDES)


all:	ptb

ptb:	ptb.c
	$(COMPILE) -lpcap -o ptb ptb.c
