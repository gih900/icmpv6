CC = cc
CFLAGS  =
CINCLUDES =
COMPILE  = $(CC) $(CFLAGS) $(CINCLUDES)


all:	ptb

ptb:	ptb.c
	$(COMPILE) -o ptb ptb.c -lpcap 
