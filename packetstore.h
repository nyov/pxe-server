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
 * packetstore.h - decode and store a packet in memory                        *
 ******************************************************************************/

#ifndef _PACKETSTORE_H
#define _PACKETSTORE_H

#include <sys/types.h>
#include <stream.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "options.h"
#include "logfile.h"
#include "sysexception.h"
#include "config.h"

#define BOOTREQUEST 1
#define BOOTREPLY 2

#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNACK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8
#define MAGIC_COOKIE 0x63825363

#define DHCP_MAX_TYPES 9
extern char *DHCP_types[DHCP_MAX_TYPES];

// some more defines
#define DISABLE_MULTICAST 0x40
#define DISABLE_BROADCAST 0x80

class PacketStore
{
	protected:
		// all multibyte values are stored
		// in network byte order internally
		uint8_t op;
		uint8_t htype;
		uint8_t hlen;
		uint8_t hops;
		uint32_t xid;
		uint16_t secs;
		struct in_addr ciaddr;
		struct in_addr yiaddr;
		struct in_addr siaddr;
		struct in_addr giaddr;
		uint8_t chaddr[16];
		char sname[64];
		char file[128];
		
		uint32_t magic_cookie;
		option *head;
		option *head43;

		struct sockaddr_in address;
		LogFile *logger;

	public:
		PacketStore(LogFile *);
		PacketStore(LogFile *, struct sockaddr_in *, uint8_t *, int);
		~PacketStore();

		option *operator () (int , int);
		int DelOption(int , int);
		int AddOption(const option *);
		void Initalise(void);
		void SetAddress(const struct sockaddr_in *);

		friend ostream& operator<< (ostream&, PacketStore&);
		int ReadPacket(uint8_t *, int);
		int MakeReply(PacketStore &, Options *, struct sockaddr_in *);
		bootp_packet *PackPacket(void);
		uint16_t GetCSA();

	private:
		uint16_t checkCSA(uint16_t);
		option *GetOption(int major_opt=0, int minor_opt=0);
		int ReadOptions(uint8_t *bootp_pkt, int bootp_pkt_len);
		int ReadOptions43(uint8_t *bootp_pkt, int bootp_pkt_len);
		uint16_t htois(uint16_t);
		uint32_t htoil(uint32_t);
		// generate reply options
		int GenOpt43(Options *, int, PacketStore &, int);
		int GenOpt54(void);
		int GenOpt60(void);

};
#endif
