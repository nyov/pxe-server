# uncoment the following 3 lines for Solaris
CC		=	g++
CFLAGS		=	-g -ggdb -Wall -DSOLARIS
LDFLAGS		=	-lsocket -lnsl -lresolv

# uncomment the following 3 lines for Linux
#CC		=	g++
#CFLAGS		=	-g -ggdb -Wall -DLINUX
#LDFLAGS		=	

# uncomment the following 3 lines for OpenBSD
#CC     =   g++
#CFLAGS     =   -g -ggdb -Wall -DOPENBSD
#LDFLAGS        =

EXECS	=	pxe
CP		=	cp

all:	$(EXECS)

pxe.o:	pxe.cc
sock.o:	sock.cc
logfile.o:	logfile.cc
options.o:	options.cc
sysexception.o:	sysexception.cc
packetstore.o:	packetstore.cc packetstore.h
posix_signal.o:	posix_signal.cc

OBJS	=	pxe.o sock.o logfile.o options.o sysexception.o \
			packetstore.o posix_signal.o

clean:
	/bin/rm -f $(EXECS) $(OBJS) *.o core a.out .nfs*

pxe:		$(OBJS)
	$(CC) $(OBJS) -o pxe $(LDFLAGS)

.cc.o:
	$(CC) $(CFLAGS) -c $*.cc

install:	all
	$(CP) pxe /usr/sbin/
	$(CP) pxe.conf /etc/
