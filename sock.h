/*
 * PXE daemon - enable the remote booting of PXE enabled machines.
 * Copyright (C) 2000 Tim Hurman (kano@kano.org.uk)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */
/******************************************************************************
 * sock.h - socket IO class                                                   *
 ******************************************************************************/

#ifndef _SOCK_H
#define _SOCK_H

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stropts.h>
#include <sys/time.h>

#ifdef SOLARIS
#include <sys/sockio.h>
#endif // SOLARIS


#include "config.h"
#include "sysexception.h"
#include "logfile.h"


struct iflist_t
{
	char *if_name;
	in_addr if_addr;
	struct iflist_t *next;
};

class Sock
{

protected:
	int *sockfds;
	int ifnum;
	uint16_t listenport;
	uint16_t clientport;

	int multi_sockfd;
	int broad_sockfd;
	int use_multi;
	int use_broad;

	struct sockaddr_in *bind_addrs;
	struct sockaddr_in multicast;
	int listen_multi;
	struct sockaddr_in broadcast;
	int listen_broad;
	struct sockaddr_in default_addr;
	LogFile *log;

public:
	// constructors
	Sock(LogFile *log, const char *interface, uint16_t port);
	~Sock();

	// methods
	int JoinMulticast(uint32_t multi_addr);
	int LeaveMulticast();
	int Read(unsigned char *, int, struct sockaddr_in *, struct sockaddr_in *);
	int Send(unsigned char *, int, struct sockaddr_in *, struct sockaddr_in *);
	int AllowBroadcast();
	int DenyBroadcast();
	char *GetHostname(const struct sockaddr_in *address);
	void SetDefAddr(uint32_t);

private:
	int Open(iflist_t *local_addr_t, int listlen, const uint16_t port);
	int Close();
	iflist_t *GetIfList();

};

#endif
