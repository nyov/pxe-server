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
 * sock.c - socket IO class defs                                              *
 ******************************************************************************/

#include "sock.h"
#include <iostream>

#ifndef _SOCKLEN_T
typedef unsigned int socklen_t;
#endif // _SOCKLEN_T


/******************************************************************************
 * Constructor                                                                *
 ******************************************************************************/
Sock::Sock(LogFile *_log, const char *interface, uint16_t port)
{
	iflist_t *start, *ptr, *prev, distinct;
	int listlen = 0;

	this->log = _log;
	listen_multi = 0;
	multi_sockfd = -1;
	sockfds = NULL;
	ifnum = 0;
	memset(&default_addr, 0, sizeof(default_addr));

	// prepare
	if(port == 0)
		port = DEF_PORT;
	default_addr.sin_port = htons(port);

	start = GetIfList();
	ptr = start;
	
	// see if the specified interface is available
	while(ptr != NULL)
	{
		listlen++;
		if(NULL != interface)
			if(strcmp(interface, ptr->if_name) == 0)
				break;
		ptr = ptr->next;
	}

	// if available, only bind to that
	if (ptr != NULL)
	{
		std::cout << "Only binding to interface " << ptr->if_name << "\n";
		distinct.if_name = ptr->if_name;
		memcpy(&(distinct.if_addr), &(ptr->if_addr), sizeof(distinct.if_addr));
		default_addr.sin_addr.s_addr = distinct.if_addr.s_addr;
		distinct.next = NULL;
		Open(&distinct, 1, port);
	}
	else
	// else all interfaces
	{
		std::cout << "Binding to all interfaces\n";
		default_addr.sin_addr.s_addr = INADDR_BROADCAST;
		Open(start, listlen, port);
	}

	prev = ptr = start;
	while(ptr != NULL)
	{
		ptr = ptr->next;
		delete[] prev->if_name;
		delete prev;
		prev = ptr;
	}
		
}


/******************************************************************************
 * GetIfList - get a list of all interfaces in the machine                    *
 ******************************************************************************/
#ifndef HAVE_GETIFADDRS
iflist_t *
Sock::GetIfList()
{
	int tmp_sockfd;
	struct ifconf ifc;
	struct sockaddr_in tmp_addr;
	iflist_t *start, *ptr;
	int pos, len, lastlen;

	tmp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(tmp_sockfd == -1)
		throw new SysException(errno, "Sock::Sock:socket()");

	lastlen=0;
	len=1024;

	while(1)
	{
		ifc.ifc_len = len;
		ifc.ifc_req = new(struct ifreq[len]);

		if(ioctl(tmp_sockfd, SIOCGIFCONF, &ifc) < 0)
			throw new SysException(errno, "Sock::Sock:ioctl()");

		if(ifc.ifc_len <= len)
			break;
		lastlen = ifc.ifc_len;
		len += 10;
		delete[] ifc.ifc_req;
		
	}
	close(tmp_sockfd);

	// allocate the first in the linked list
	start = new iflist_t;
	start->next = NULL;
	ptr = start;

	/* go throught the struct and pick out the info */
	pos=0;
	while(1)
	{
		ptr->if_name = new char[strlen(ifc.ifc_req[pos].ifr_name)+1];
		strcpy(ptr->if_name, ifc.ifc_req[pos].ifr_name);
		std::cout << "Found interface " << ifc.ifc_req[pos].ifr_name << "\n";

		// tidy this up, too many ops
		memcpy(&tmp_addr, &(ifc.ifc_req[pos].ifr_addr), sizeof(tmp_addr));
		memcpy(&(ptr->if_addr), &(tmp_addr.sin_addr), sizeof(ptr->if_addr));

		// do we leave now?
		pos++;
		if(((pos)*sizeof(struct ifreq)) >= (unsigned)ifc.ifc_len)
			break;

		// allocate the new item
		ptr->next = new iflist_t;
		ptr = ptr->next;
		ptr->next = NULL;
	}

	delete[] ifc.ifc_req;
	return(start);
}
#else

iflist_t *
Sock::GetIfList()
{
	struct ifaddrs *ifap, *ifptr;
	struct sockaddr_in tmp_addr;
	iflist_t *start, *ptr, *prevptr;

	// get an interface list
	if(-1 == getifaddrs(&ifap))
	{
		log->Event(LEVEL_INFO, "Sock::GetIfList", 1,
		  "Unable to get interface list");
		return(NULL);
	}

	// allocate the first in the linked list
	start = ptr = prevptr = NULL;

	// go through the list
	ifptr = ifap;
	for(ifptr = ifap; ifptr; ifptr = ifptr->ifa_next) {
		if(!(ifptr->ifa_addr) || AF_INET != ifptr->ifa_addr->sa_family)
			continue;

		ptr = new iflist_t;
		ptr->next = NULL;
		if(NULL == start)
			start = prevptr = ptr;
		else
		{
			prevptr->next = ptr;
			prevptr = ptr;
		}

		ptr->if_name = new char[strlen(ifptr->ifa_name)+1];
		strcpy(ptr->if_name, ifptr->ifa_name);
		std::cout << "Found interface " << ifptr->ifa_name << "\n";

		// tidy this up, too many ops
		memcpy(&tmp_addr, ifptr->ifa_addr, sizeof(tmp_addr));
		memcpy(&(ptr->if_addr), &(tmp_addr.sin_addr), sizeof(ptr->if_addr));
		ptr->next = NULL;
	}
	
	// free the interface list
	freeifaddrs(ifap);
	return(start);
}
#endif // HAVE_GETIFADDRS


/******************************************************************************
 * Destructor                                                                 *
 ******************************************************************************/
Sock::~Sock()
{
	Close();

	delete[] sockfds;
	delete[] bind_addrs;
	ifnum = 0;
}


/******************************************************************************
 * Destructor                                                                 *
 ******************************************************************************/
void
Sock::SetDefAddr(uint32_t addr)
{
	if((addr != 0) && (default_addr.sin_addr.s_addr != 0))
		default_addr.sin_addr.s_addr = htonl(addr);
}


/******************************************************************************
 * Open - open a socket bound to and addr and ready to listen on another      *
 ******************************************************************************/
int
Sock::Open(iflist_t *local_addrs, int listlen, const uint16_t port)
{
	int tmp;
	struct servent *bootpc_port;
	iflist_t *lptr;
	int pos;

	/* initalise vars */
	lptr = local_addrs;
	listen_multi = 0;
	listen_broad = 0;
	ifnum = listlen;

	/* sockfds */
	sockfds = new int[ifnum];
	bind_addrs = new struct sockaddr_in[ifnum];

	/* get the port */
	listenport = htons(port);
	bootpc_port = getservbyname(BOOTPC_NAME, "udp");
	if(bootpc_port == NULL)
		throw new SysException(errno, "Sock::Open:getservbyname()");
	
	clientport = bootpc_port->s_port;

	for(pos=0; lptr != NULL; pos++)
	{
		/* fill the structs */
		bzero(&bind_addrs[pos], sizeof(bind_addrs[pos]));
		bind_addrs[pos].sin_family = AF_INET;
		bind_addrs[pos].sin_port = listenport;
		memcpy(&(bind_addrs[pos].sin_addr), &(lptr->if_addr),
			sizeof(bind_addrs[pos].sin_addr));
		std::cout << "Binding to: " <<
		  inet_ntoa(bind_addrs[pos].sin_addr) << "\n";

		/* create a socket */
		sockfds[pos] = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(sockfds[pos] == -1)
			throw new SysException(errno, "Sock::Open:socket()");

		/* allow socket re-use */
		tmp = 1;
		if(setsockopt(sockfds[pos], SOL_SOCKET, SO_REUSEADDR,
			(const char*)&tmp, sizeof(tmp)) == -1)
			throw new SysException(errno, "Sock::Open:setsockopt(REUSE)");

		/* bind the socket to a specific local interface */
		if(bind(sockfds[pos], (struct sockaddr*)&bind_addrs[pos],
				sizeof(bind_addrs[pos])) != 0)
			throw new SysException(errno, "Sock::Open:bind()");

		/* report that we have bound the interface */
		char *tmpbuf = new char[16];
		sprintf(tmpbuf, "%d", port);
		log->Event(LEVEL_INFO, "Sock::Open", 4, "Bound to address:",
			inet_ntoa(lptr->if_addr), "Port:", tmpbuf);
		delete[] tmpbuf;

		/* move forward a position */
		lptr = lptr->next;
	}

	/* return */
	return(0);
}


/******************************************************************************
 * JoinMulticast - join a multicast group                                     *
 ******************************************************************************/
int
Sock::JoinMulticast(uint32_t multi_addr)
{
	unsigned char tchar;
	struct ip_mreq mreq;
	struct sockaddr_in local;

	if(listen_multi == 1)
		return(0); // already listening

	/* passed a null addr */
	if(multi_addr == 0)
		throw new SysException(0, "Sock::JoinMulticast", "No address specified");

	/* is the address actually a multicast address */
	if(!IN_MULTICAST(multi_addr))
		throw new SysException(0, "Sock::JoinMulticast",
			"Address specified is not a multicast address");

	/* fill the struct */
	listenport = htons(4011);
	memset(&multicast, 0, sizeof(multicast));
	multicast.sin_family = AF_INET;
	multicast.sin_port = listenport; // already in net order
	multicast.sin_addr.s_addr = htonl(multi_addr);
	/* local */
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = listenport; // already in net order
	local.sin_addr.s_addr = htonl(INADDR_ANY);

	/* create a socket */
	multi_sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if(multi_sockfd == -1)
		throw new SysException(errno, "Sock::JoinMulticast:socket()");

	/* allow socket re-use */
	int tmp = 1;
	if(setsockopt(multi_sockfd, SOL_SOCKET, SO_REUSEADDR,
	  (const char*)&tmp, sizeof(tmp)) == -1)
		throw new SysException(errno,
		  "Sock::JoinMulticast:setsockopt(REUSE)");

	/* bind to the multicast address */
	if(bind(multi_sockfd, (struct sockaddr*)&local, sizeof(local)) != 0)
		throw new SysException(errno, "Sock::JoinMulticast:bind()");
	
	/* setup the multicast struct */
	mreq.imr_interface.s_addr = local.sin_addr.s_addr;
	mreq.imr_multiaddr.s_addr = multicast.sin_addr.s_addr;
	
	/* join a multicast group */
	if(setsockopt(multi_sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		(const char*)&mreq, sizeof(mreq)) == -1)
		throw new SysException(errno, "Sock::JoinMulticast:setsockopt(ADD)");

	/* Dont go outside the local net */
	tchar = 1;
	if(setsockopt(multi_sockfd, IPPROTO_IP, IP_MULTICAST_TTL,
		(const char *)&tchar, sizeof(tchar)) == -1)
		throw new SysException(errno, "Sock::JoinMulticast:setsockopt(TTL)");

	/* Dont receive sent packets */
	tchar = 0;
	if(setsockopt(multi_sockfd, IPPROTO_IP, IP_MULTICAST_LOOP,
		(const char *)&tchar, sizeof(tchar)) == -1)
		throw new SysException(errno, "Sock::JoinMulticast:setsockopt(LOOP)");

	log->Event(LEVEL_INFO, "Sock::JoinMulticast", 1,
		"Joined multicast group", inet_ntoa(mreq.imr_multiaddr));
	// we are now listening
	listen_multi = 1;

	return(0);
}


/******************************************************************************
 * LeaveMulticast - leave a multicast group                                   *
 ******************************************************************************/
int
Sock::LeaveMulticast()
{
	struct ip_mreq mreq;

	/* setup the multicast struct */
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	mreq.imr_multiaddr.s_addr = multicast.sin_addr.s_addr;

	/* leave a sock group */
	if(setsockopt(multi_sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
		(const char*)&mreq, sizeof(mreq)) == -1)
		throw new SysException(errno, "Sock::LeaveMulticast:setsockopt(DROP)");

	/* close */
	shutdown(multi_sockfd, 2);
	close(multi_sockfd);

	log->Event(LEVEL_INFO, "Sock::LeaveMulticast", 1,
		"Left multicast group", inet_ntoa(mreq.imr_multiaddr));
	listen_multi = 0;
	return(0);
}


/******************************************************************************
 * AllowBroadcast - allow broadcasts                                          *
 ******************************************************************************/
int
Sock::AllowBroadcast()
{
	int tmp=1;
	int pos = 0;

	for(pos=0; pos < ifnum; pos++)
	{
		if(setsockopt(sockfds[pos], SOL_SOCKET, SO_BROADCAST,
		  (const char *)&tmp, sizeof(tmp)) == -1)
			throw new SysException(errno, "Sock::AllowBroadcast:setsockopt()");
	}
	log->Event(LEVEL_INFO, "Sock::AllowBroadcast", 1, "Allowing broadcasts");
	listen_broad = 1;
	return(0);
}


/******************************************************************************
 * DenyBroadcast - deny broadcasts                                            *
 ******************************************************************************/
int
Sock::DenyBroadcast()
{
	int tmp=0;
	int pos = 0;

	for(pos=0; pos < ifnum; pos++)
	{
		if(setsockopt(sockfds[pos], SOL_SOCKET, SO_BROADCAST,
		  (const char *)&tmp, sizeof(tmp)) == -1)
			throw new SysException(errno, "Sock::DenyBroadcast:setsockopt()");
	}

	log->Event(LEVEL_INFO, "Sock::DenyBroadcast", 1, "Disallowing broadcasts");
	listen_broad = 0;
	return(0);
}


/******************************************************************************
 * Close - close a routing socket                                             *
 ******************************************************************************/
int
Sock::Close()
{
	int pos;

	if(listen_broad)
		DenyBroadcast();

	if(listen_multi)
		LeaveMulticast();

	for(pos=0; pos < ifnum; pos++)
	{
		shutdown(sockfds[pos], 2);
		close(sockfds[pos]);
	}

	log->Event(LEVEL_INFO, "Sock::Close", 1, "Released interface(s)");
	return(0);
}


/******************************************************************************
 * Read - read some data from the socket                                      *
 ******************************************************************************/
int
Sock::Read(unsigned char *buf, int maxlen, struct sockaddr_in *client_addr,
	struct sockaddr_in *server_addr)
{
	int readlen=0;
	int size;
	int pos;
	int selret;
	int maxfdno=0;
	int livefd = 0;
	fd_set fdset;
	struct sockaddr_in *from=NULL;

	// get the max fd no
	if(NULL != sockfds)
		for(pos = 0; pos < ifnum; pos++)
			if(sockfds[pos] > maxfdno)
				maxfdno = sockfds[pos];

	if((listen_multi == 1) && (multi_sockfd > maxfdno))
		maxfdno = multi_sockfd;
	maxfdno++;

	// need to select from all sockets
	while(true)
	{
		// register all of the fd numbers
		FD_ZERO(&fdset);
		if(NULL != sockfds)
			for(pos = 0; pos < ifnum; pos++)
				FD_SET(sockfds[pos], &fdset);
		if(listen_multi == 1)
			FD_SET(multi_sockfd, &fdset);

		// wait for the next packet
		selret = select(maxfdno, &fdset, NULL, NULL, NULL);
		if(selret == -1)
			if(errno == EINTR)
				break;
			else
				throw new SysException(errno, "Sock::Read:select()");

		// how many fds setup?
		if(selret < 1) goto Sock_Read_next;

		// where did it come from?
		if(NULL != sockfds)
			for(pos = 0; pos < ifnum; pos++)
				if(FD_ISSET(sockfds[pos], &fdset)) {
					livefd = sockfds[pos];
					from = &(bind_addrs[pos]);
					break;
				}

		// was the multicast fd set
		if(listen_multi && FD_ISSET(multi_sockfd, &fdset)) {
			from  = &default_addr;
			livefd = multi_sockfd;
		}

		// read the next packet
		size=sizeof(struct sockaddr_in);
		readlen = recvfrom(livefd, (char*)buf, maxlen, 0,
			(struct sockaddr*)client_addr, (socklen_t*)&size);
	
		if(readlen == -1)
			if(errno == EINTR)
				break;
			else
				throw new SysException(errno, "Sock::Read:read()");

		if(readlen == 0)
			goto Sock_Read_next;

		// copy the server address
		memcpy(server_addr, from, sizeof(*from));

		// receive any packet on unicast/multicast/broadcast
		if((client_addr->sin_port == clientport) ||
		   (livefd == multi_sockfd)) // HACK!
			break;

		Sock_Read_next:
		size=size;
	}

	return(readlen);
}


/******************************************************************************
 * GetHostname - get the hostname of the connected socket                     *
 ******************************************************************************/
char *
Sock::GetHostname(const struct sockaddr_in *address)
{
	struct hostent *h_info;

	// get the address info
	h_info = gethostbyaddr((const char*)&(address->sin_addr.s_addr),
	   sizeof(address->sin_addr.s_addr), AF_INET);
	if(h_info == NULL)
	{
#ifdef HAVE_HSTRERROR
		log->Event(LEVEL_INFO, "Sock::GetHostname:gethostbyaddr()",
			1, hstrerror(h_errno));
#else
		log->Event(LEVEL_INFO, "Sock::GetHostname:gethostbyaddr()",
			1, "Resolver error occourred");
#endif
		return(NULL);
	}

	return(h_info->h_name);
}


/******************************************************************************
 * Send - send some data to the client                                        *
 ******************************************************************************/
int
Sock::Send(unsigned char *buf, int maxlen, struct sockaddr_in *client_addr,
	struct sockaddr_in *server_addr)
{
	int livefd=0;
	int ifno, len;
	int found = 0;

	// firstly, make some routing choices
	for(ifno=0; ifno < ifnum; ifno++)
	{
		if(bind_addrs[ifno].sin_addr.s_addr == server_addr->sin_addr.s_addr)
		{
			livefd = sockfds[ifno];
			found++;
			break;
		}
	}

	if(multicast.sin_addr.s_addr == server_addr->sin_addr.s_addr)
	{
		found++;
		livefd = multi_sockfd;
	}

	// which interface?
	if(found == 0)
		throw new SysException(1, "Sock::Send", "Not bound to interface");

	// send the message
	len = sendto(livefd, (char*)buf, maxlen, 0,
	  (struct sockaddr*)client_addr, sizeof(struct sockaddr_in));
	// ok?
	if(-1 == len)
		throw new SysException(errno, "Sock::Send:sendto()");

	if(maxlen != len)
		throw new SysException(1, "Sock::Send", "Packet truncated");

	return(len);
}
