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
 * packetstore.cc - decode and store a packet in memory                       *
 ******************************************************************************/

#include "packetstore.h"

/* some global variables */
const char *DHCP_types[DHCP_MAX_TYPES] = 
{
	"INVALID", "DHCPDISCOVER", "DHCPOFFER", "DHCPREQUEST",
	"DHCPDECLINE", "DHCPACK", "DHCPNACK", "DHCPRELEASE",
	"DHCPINFORM"
};

/******************************************************************************
 * PacketStore - null packet constructor                                      *
 ******************************************************************************/
PacketStore::PacketStore(LogFile *_logger)
{
	this->logger = _logger;
	head = head43 = NULL;
	Initalise();
}


/******************************************************************************
 * PacketStore - full packet analyse                                          *
 ******************************************************************************/
PacketStore::PacketStore(LogFile *_logger, struct sockaddr_in *_address,
	uint8_t *bootp_pkt, int bootp_pkt_len)
{
	this->logger = _logger;
	memcpy(&(this->address), _address, sizeof(this->address));
	ReadPacket(bootp_pkt, bootp_pkt_len);
}


/******************************************************************************
 * ~PacketStore - descructor                                                  *
 ******************************************************************************/
PacketStore::~PacketStore()
{
	Initalise();
}


/******************************************************************************
 * Initalise - init/blank a packet                                            *
 ******************************************************************************/
void
PacketStore::Initalise(void)
{
	option *optptr, *optnext;

	// basic stuff 
	op=htype=hlen=hops=0;
	secs=0;
	xid=0;
	memset(chaddr, 0, 16);
	sname[0] = file[0] = 0;
	magic_cookie = 0;
	
	memset(&ciaddr, 0, sizeof(ciaddr));
	memset(&yiaddr, 0, sizeof(yiaddr));
	memset(&siaddr, 0, sizeof(siaddr));
	memset(&giaddr, 0, sizeof(giaddr));
	memset(&address, 0, sizeof(giaddr));

	// options
	for(optptr=head; optptr != NULL; optptr=optnext)
	{
		optnext = optptr->next;
		delete[] optptr->data;
		delete optptr;
	}
	head = NULL;

	// options 43
	for(optptr=head43; optptr != NULL; optptr=optnext)
	{
		optnext = optptr->next;
		delete[] optptr->data;
		delete optptr;
	}
	head43 = NULL;
}


/******************************************************************************
 * ReadPacket - read a bootp packet                                           *
 ******************************************************************************/
int
PacketStore::ReadPacket(uint8_t *bootp_pkt, int bootp_pkt_len)
{
	if(bootp_pkt_len < 300)
		throw new SysException(0, "PacketStore::ReadPacket",
			"Invalid packet length");

	op = bootp_pkt[0];
	htype = bootp_pkt[1];
	hlen = bootp_pkt[2];
	hops = bootp_pkt[3];

	// xid - store in network byte order
	xid = bootp_pkt[4];
	xid <<= 8;
	xid |= bootp_pkt[5];
	xid <<= 8;
	xid |= bootp_pkt[6];
	xid <<= 8;
	xid |= bootp_pkt[7];
	xid = htonl(xid);

	// no of secs
	secs = bootp_pkt[8];
	secs <<= 8;
	secs |= bootp_pkt[9];
	secs = htons(secs);

	// client IP addr (filled in by client)
	ciaddr.s_addr = bootp_pkt[12];
	ciaddr.s_addr <<= 8;
	ciaddr.s_addr |= bootp_pkt[13];
	ciaddr.s_addr <<= 8;
	ciaddr.s_addr |= bootp_pkt[14];
	ciaddr.s_addr <<= 8;
	ciaddr.s_addr |= bootp_pkt[15];
	ciaddr.s_addr = htonl(ciaddr.s_addr);

	// client IP addr (filled in by server)
	yiaddr.s_addr = bootp_pkt[16];
	yiaddr.s_addr <<= 8;
	yiaddr.s_addr |= bootp_pkt[17];
	yiaddr.s_addr <<= 8;
	yiaddr.s_addr |= bootp_pkt[18];
	yiaddr.s_addr <<= 8;
	yiaddr.s_addr |= bootp_pkt[19];
	yiaddr.s_addr = htonl(yiaddr.s_addr);

	// server IP address (filled in by server)
	siaddr.s_addr = bootp_pkt[20];
	siaddr.s_addr <<= 8;
	siaddr.s_addr |= bootp_pkt[21];
	siaddr.s_addr <<= 8;
	siaddr.s_addr |= bootp_pkt[22];
	siaddr.s_addr <<= 8;
	siaddr.s_addr |= bootp_pkt[23];
	siaddr.s_addr = htonl(siaddr.s_addr);

	// gateway IP address
	giaddr.s_addr = bootp_pkt[24];
	giaddr.s_addr <<= 8;
	giaddr.s_addr |= bootp_pkt[25];
	giaddr.s_addr <<= 8;
	giaddr.s_addr |= bootp_pkt[26];
	giaddr.s_addr <<= 8;
	giaddr.s_addr |= bootp_pkt[27];
	giaddr.s_addr = htonl(giaddr.s_addr);

	// client hardware address
	memcpy(chaddr, bootp_pkt+28, 16);

	// the servername
	if(bootp_pkt[107] != 0)
		throw new SysException(0, "PacketStore::ReadPacket",
			"Invalid servername");
	strcpy(sname, (char*)bootp_pkt+44);

	// the file
	if(bootp_pkt[235] != 0)
		throw new SysException(0, "PacketStore::ReadPacket",
			"Invalid filename");
	strcpy(file, (char*)bootp_pkt+108);

	// the magic cookie
	magic_cookie = bootp_pkt[236];
	magic_cookie <<= 8;
	magic_cookie |= bootp_pkt[237];
	magic_cookie <<= 8;
	magic_cookie |= bootp_pkt[238];
	magic_cookie <<= 8;
	magic_cookie |= bootp_pkt[239];
	magic_cookie = htonl(magic_cookie);

	if(bootp_pkt[236] == 0xff)
		return(0);
	
	// read the options
	head=head43=NULL;
	return(ReadOptions(bootp_pkt+240, bootp_pkt_len-240));
}


/******************************************************************************
 * print the packet to stdout                                                 *
 ******************************************************************************/
std::ostream&
operator<< (std::ostream& os, PacketStore &pkt)
{
	int i;
	option *optptr;

	// basic info
	os << "BOOTP type             : " << (int)pkt.op << "\n";
	os << "Hardware type          : " << (int)pkt.htype << "\n";
	os << "Hardware Length        : " << (int)pkt.hlen << "\n";
	os << "Hops                   : " << (int)pkt.hops << "\n";
	os << "Transaction ID         : 0x" << std::hex << ntohl(pkt.xid) <<
	  std::dec <<"\n";
	os << "Seconds                : " << ntohs(pkt.secs) << "\n";
	os << "Client IP (From Client): " << inet_ntoa(pkt.ciaddr) << "\n";
	os << "Client IP (From Server): " << inet_ntoa(pkt.yiaddr) << "\n";
	os << "Server IP              : " << inet_ntoa(pkt.siaddr) << "\n";
	os << "Gateway IP             : " << inet_ntoa(pkt.giaddr) << "\n";
	os << "Client Hardware address: " ;
	
	// client hardware addr
	for(i=0; i<pkt.hlen; i++)
		os << std::hex << (int)pkt.chaddr[i] << std::dec << ".";
	os << "\n";

	// string info
	os << "Server name            : " << pkt.sname << "\n";
	os << "Boot filename          : " << pkt.file << "\n";
	os << "Magic cookie           : 0x" << std::hex <<
	  ntohl(pkt.magic_cookie) << std::dec  << "\n";

	if(pkt.head == NULL)
		return os;

	// print the options
	os << "Options                :\n";

	for(optptr = pkt.head; optptr != NULL; optptr = optptr->next)
	{
		os << "Option major:" << (int)optptr->major_no
		   << " minor: " << (int)optptr->minor_no
		   << ", Length: " << (int)optptr->len << ", Data: ";
		for(i=0; i<optptr->len; i++)
			if((optptr->data[i] >0x20) && (optptr->data[i] < 0x7f))
				os << "[" << (int)optptr->data[i]
				   << "," << std::hex << (int)optptr->data[i] << std::dec
				   << "," << (char)optptr->data[i] << "] ";
			else
				os << "[" << (int)optptr->data[i]
				   << "," << std::hex << (int)optptr->data[i] << std::dec
				   << ", ] ";

		os << "\n";
	}

	if(pkt.head43 == NULL)
		return os;
			
	// option 43
	os << "Options (sub-packed)   :\n";
	for(optptr = pkt.head43; optptr != NULL; optptr = optptr->next)
	{
		os << "Option [43] " << (int)optptr->major_no
		   << " minor: " << (int)optptr->minor_no
		   << ", Length: " << (int)optptr->len << ", Data: ";
		for(i=0; i<optptr->len; i++)
			if((optptr->data[i] >0x20) && (optptr->data[i] < 0x7f))
				os << "[" << (int)optptr->data[i]
				   << "," << std::hex << (int)optptr->data[i] << std::dec 
				   << "," << (char)optptr->data[i] << "] ";
			else
				os << "[" << (int)optptr->data[i]
				   << "," << std::hex << (int)optptr->data[i] << std::dec
				   << ", ] ";

		os << "\n";
	}

	return os;
}


/******************************************************************************
 * ReadOptions - read all the options contained within a packet               *
 ******************************************************************************/
int
PacketStore::ReadOptions(uint8_t *bootp_pkt, int bootp_pkt_len)
{
	// everything will always be null here
	int pos;
	option *optptr = NULL;
	option *optprev = NULL;

	for(pos=0; pos < bootp_pkt_len; pos++)
	{
		if(bootp_pkt[pos] == 0)
			goto ReadOptions_next; // pad

		if(bootp_pkt[pos] == 255)
			break;	// end options

		// lots of sub options
		if(bootp_pkt[pos] == 43)
		{
			ReadOptions43(bootp_pkt+pos+2, bootp_pkt[pos+1]);
			pos += bootp_pkt[pos+1]+1;
			goto ReadOptions_next; // next
		}

		// default
		optptr = new option;
		optptr->major_no = bootp_pkt[pos++];
		optptr->minor_no = 0;
		optptr->len = bootp_pkt[pos++];
		optptr->data = new uint8_t[optptr->len];
		optptr->next = NULL;
		memcpy(optptr->data, bootp_pkt+pos, optptr->len);

		// increment pos, accounting to cyclic increment
		pos += (optptr->len-1);

		if(head != NULL)
		{
			optprev->next = optptr; // assign
			optprev = optprev->next; // advance
		}
		else
			optprev = head = optptr;

		ReadOptions_next:
		pos=pos;
	}

	return(0);
}


/******************************************************************************
 * ReadOptions43 - read all the options contained within a packet             *
 ******************************************************************************/
int
PacketStore::ReadOptions43(uint8_t *bootp_pkt, int bootp_pkt_len)
{
	// everything will always be null here
	int pos;
	option *optptr=NULL;
	option *optprev=NULL;

	for(pos=0; pos < bootp_pkt_len; pos++)
	{
		if(bootp_pkt[pos] == 0)
			goto ReadOptions43_next; // pad

		if(bootp_pkt[pos] == 255)
			break;	// end options

		// lots of sub options
		if(bootp_pkt[pos] == 43)
		{
			std::cerr << "Option 43 detected\n";
			break;
		}

		// default
		optptr = new option;
		optptr->major_no = 43;
		optptr->minor_no = bootp_pkt[pos++];
		optptr->len = bootp_pkt[pos++];
		optptr->data = new uint8_t[optptr->len];
		optptr->next = NULL;
		memcpy(optptr->data, bootp_pkt+pos, optptr->len);

		// increment pos, accounting to cyclic increment
		pos += (optptr->len-1);

		if(head43 != NULL)
		{
			optprev->next = optptr; // assign
			optprev = optprev->next; // advance
		}
		else
			optprev = head43 = optptr;

		ReadOptions43_next:
		pos=pos;
	}

	return(0);
}


/******************************************************************************
 * operator() - get an option from the list                                   *
 ******************************************************************************/
option *
PacketStore::operator()(int major_opt=0, int minor_opt=0)
{
	return(GetOption(major_opt, minor_opt));
}


/******************************************************************************
 * GetOption - get an option fromthe option list                              *
 ******************************************************************************/
option *
PacketStore::GetOption(int major_opt=0, int minor_opt=0)
{
	option *opt = new option;
	option *optptr;

	if(major_opt == 43)
		optptr = head43;
	else
		optptr = head;
	
	for(; optptr != NULL; optptr = optptr->next)
		if((major_opt == optptr->major_no) &&
		   (minor_opt == optptr->minor_no))
			break;
	
	if(optptr == NULL)
		return(NULL);

	opt->major_no = optptr->major_no;
	opt->minor_no = optptr->minor_no;
	opt->len = optptr->len;
	opt->next = NULL;
	opt->data = new uint8_t[opt->len];
	memcpy(opt->data, optptr->data, opt->len);

	return(opt);
}


/******************************************************************************
 * DelOption - delete an option from the list                                 *
 ******************************************************************************/
int
PacketStore::DelOption(int major_opt=0, int minor_opt=0)
{
	option *optptr, *optprev;

	if(major_opt == 43)
		optptr = optprev = head43;
	else
		optptr = optprev = head;

	for(; ((major_opt != optptr->major_no) &&
	       (minor_opt != optptr->minor_no)) ||
	       (optptr != NULL); optptr = optptr->next)
		optprev = optptr;

	if(optptr != NULL) // option found
	{
		// re-arrange the pointers
		if(optprev == optptr) // head
			if(optptr == head43)
				head43 = optptr->next;
			else
				head = optptr->next;
		else
			optprev->next = optptr->next;

		// delete the memory
		delete[] optptr->data;
		delete optptr;
	}
	else
		return(1); // no found

	return(0);
}


/******************************************************************************
 * AddOption - add an option to the list (overwrite)                          *
 ******************************************************************************/
int
PacketStore::AddOption(const option *opt)
{
	option *optptr, *optprev;

	if(opt->major_no == 43)
		optptr = optprev = head43;
	else
		optptr = optprev = head;

	// find the entry or null;
	while(optptr != NULL)
	{
		if((opt->major_no != optptr->major_no) &&
		   (opt->minor_no != optptr->minor_no))
			break;
		optprev = optptr;
		optptr = optptr->next;
	}

	if(optptr == NULL) // new item
	{
		optptr = new option;
		optptr->major_no = opt->major_no;
		optptr->minor_no = opt->minor_no;
		optptr->next = NULL;

		if((43 == opt->major_no) && (NULL == head43))
			head43 = optptr;
		else if(NULL == head)
			head = optptr;
		else
			optprev->next = optptr;
	}
	else  // old item
	{
		delete[] optptr->data;
	}

	optptr->len = opt->len;
	optptr->data = new uint8_t[optptr->len];
	memcpy(optptr->data, opt->data, opt->len);

	return(0);
}


/******************************************************************************
 * htois - host to intel order (short)                                        *
 ******************************************************************************/
uint16_t
PacketStore::htois(uint16_t value)
{
	uint8_t t1, t2;
	uint16_t val;

	// convert to a standard
	val = htons(value);

	// check if we need to go any further
	// since Intel order != network order
	if(val != value)
		return(value);

	// we now have a standard, can you read this Intel?, this is
	// STANDARD!

	// we know that Intel ordering is the opposite to network byte ordering
	// so just swap bytes all the way through
	// out
	t1 = (val & 0x00ff);
	t2 = (val & 0xff00) >> 8;
	// in
	val = (t1<<8);
	val |= t2;
	// we are now in a non-standard
	return val;
}


/******************************************************************************
 * htoil - host to intel order (long)                                         *
 ******************************************************************************/
uint32_t
PacketStore::htoil(uint32_t value)
{
	uint8_t t1, t2, t3, t4;
	uint32_t val;

	// convert to a standard
	val = htonl(value);

	// check if we need to go any further
	// since Intel order != network order
	if(val != value)
		return(value);

	// we now have a standard, can you read this Intel?, this is
	// STANDARD!

	// we know that Intel ordering is the opposite to network byte ordering
	// so just swap bytes all the way through
	// out
	t1 = (val & 0x000000ff);
	t2 = (val & 0x0000ff00) >> 8;
	t3 = (val & 0x00ff0000) >> 16;
	t4 = (val & 0xff000000) >> 24;
	// in
	val = (t1<<24);
	val |= (t2<<16);
	val |= (t3<<8);
	val |= (t4);

	return(val);
}


/******************************************************************************
 * SetAddress - set the address fiel of the packet (from/to)                  *
 ******************************************************************************/
void
PacketStore::SetAddress(const struct sockaddr_in *_address)
{
	memcpy(&address, _address, sizeof(address));
}


/******************************************************************************
 * MakeReply - generate a reply to an incoming request                        *
 ******************************************************************************/
int
PacketStore::MakeReply(PacketStore &request, Options *config,
	struct sockaddr_in *server_addr)
{
	// local vars
	option *opt = NULL;
	option *req_list = NULL;
	int pkttype = 0;
	uint16_t reqCSA;

	// first, check for a valid bootp packet
	if(BOOTREQUEST != request.op)
	{
		logger->Event(LEVEL_INFO, "MakeReply", 1,
		  "Packet is not a bootp request");
		return(-1);
	}

	// valid client system arch?
	reqCSA = request.GetCSA();
	if((uint16_t)-1 == reqCSA)
	{
		logger->Event(LEVEL_INFO, "MakeReply", 1,
		  "packet contains an unknown client system architecture");
		return(-1);
	}
	
	// see if there are any menus for this packet
	if((uint16_t)-1 == config->CheckMenu(reqCSA))
		return(-1);

	// next, check what the packet type was
	opt = request(43,71);
	if(opt == NULL)
	{
		logger->Event(LEVEL_INFO, "MakeReply", 1,
		  "Received proxy DHCP packet");
		pkttype = 1;
	}
	else
	{
		delete[] opt->data;
		delete opt;
		logger->Event(LEVEL_INFO, "MakeReply", 1,
		  "Received PXE request packet");
		pkttype = 2;
	}

	// was it a valid request packet?
	opt = request(53);
	if((NULL == opt) || (DHCPREQUEST != opt->data[0]))
	{
		logger->Event(LEVEL_INFO, "MakeReply", 1,
		  "Packet does not contain a valid DHCP message type");
		return(-1);
	}
	opt->data[0] = DHCPACK;
	opt->len = 1;
	AddOption(opt);
	delete[] opt->data;
	delete opt;

	// is the param request list ok?
	req_list = request(55);
	if(NULL == req_list)
	{
		logger->Event(LEVEL_INFO, "MakeReply", 1,
			"No parameter request list found");
		return(-1);
	}

	// good packet ok, build reply
	memset(file, 0, 128);
	memset(sname, 0, 64);

	// copy over the basic info
	op = BOOTREPLY;
	htype = request.htype;
	hlen = request.hlen;
	hops = request.hops;
	xid = request.xid;
	secs = request.secs;
	magic_cookie = htonl(MAGIC_COOKIE);

	// slightly harder
	memcpy(chaddr, request.chaddr, 16);
	memset(&ciaddr, 0, sizeof(ciaddr));
	memset(&yiaddr, 0, sizeof(yiaddr));
	memcpy(&siaddr, &(server_addr->sin_addr), sizeof(siaddr));
	memset(&giaddr, 0, sizeof(yiaddr));

	// set the destination address
	memcpy(&address, &(request.address), sizeof(address));

	// good, now go through the option list
	for(int i=0; i < req_list->len; i++)
		switch(req_list->data[i])
		{
		case 43:
			if(-1 == GenOpt43(config, reqCSA, request, pkttype))
				return(-1);
			break;
		case 54:
			GenOpt54();
			break;
		case 60:
			GenOpt60();
			break;
		}

	return(0);
}


/******************************************************************************
 * GenOpt43 - generate reply options                                          *
 ******************************************************************************/
int
PacketStore::GenOpt43(Options *config, int reqCSA, PacketStore &request,
 int pkttype)
{
	option opt, *optptr;
	struct sockaddr_in t_addr;
	char *tmpc;
	int arch_id, menu_id;
	uint8_t req_layer;
	int tmpi;

	opt.major_no = 43;

	// Proxy DHCP packet
	if(1 == pkttype)
	{

		// minor 1
		opt.minor_no = 1;
		t_addr.sin_addr.s_addr = htonl(config->GetMTFTPAddr());
		opt.len = sizeof(t_addr.sin_addr.s_addr);
		opt.data = new uint8_t[opt.len];
		memcpy(opt.data, &(t_addr.sin_addr.s_addr), opt.len);
		AddOption(&opt);
		delete [] opt.data;

		// minor 2 - n.b. Intel byte ordering - do intel have no common sense?
		opt.minor_no = 2;
		t_addr.sin_port = htois(config->GetMTFTPcport());
		opt.len = sizeof(t_addr.sin_port);
		opt.data = new uint8_t[opt.len];
		memcpy(opt.data, &(t_addr.sin_port), opt.len);
		AddOption(&opt);
		delete [] opt.data;

		// minor 3 - again Intel's bel^Wbig endian
		opt.minor_no = 3;
		t_addr.sin_port = htois(config->GetMTFTPsport());
		opt.len = sizeof(t_addr.sin_port);
		opt.data = new uint8_t[opt.len];
		memcpy(opt.data, &(t_addr.sin_port), opt.len);
		AddOption(&opt);
		delete [] opt.data;

		// minor 4
		opt.minor_no = 4;
		opt.len = 1;
		opt.data = new uint8_t[opt.len];
		opt.data[0] = MTFTP_OPEN_TIMEOUT;
		AddOption(&opt);

		// minor 5
		opt.minor_no = 5;
		opt.data[0] = MTFTP_REOPEN_TIMEOUT;
		AddOption(&opt);

		// minor 6
		opt.minor_no = 6;
		opt.data[0] = 0;
		// check for disabled broad/multicast
		if(0 == config->UseMulticast())
			opt.data[0] |= DISABLE_MULTICAST;
		if(0 == config->UseBroadcast())
			opt.data[0] |= DISABLE_BROADCAST;
		AddOption(&opt);
		delete [] opt.data;

		// minor 7
		opt.minor_no = 7;
		t_addr.sin_addr.s_addr = htonl(config->GetMulticast());
		opt.len = sizeof(t_addr.sin_addr.s_addr);
		opt.data = new uint8_t[opt.len];
		memcpy(opt.data, &(t_addr.sin_addr.s_addr), opt.len);
		AddOption(&opt);
		delete [] opt.data;

		// minor 9 - will always be ok, as we checked the menus earlier
		optptr = config->MakeBootMenu(reqCSA, &arch_id, &menu_id);
		optptr->major_no = 43;
		optptr->minor_no = 9;
		AddOption(optptr);
		delete [] optptr->data;
		delete optptr;
	
		// minor 10 - the menu
		opt.minor_no = 10;
		tmpc = config->GetMenuPrompt();
		opt.len = strlen(tmpc)+1;
		opt.data = new uint8_t[opt.len];
		opt.data[0] = config->GetMenuTimeout();
		memcpy(opt.data+1, tmpc, opt.len-1);
		AddOption(&opt);
		delete [] opt.data;
		delete [] tmpc;

		// minor 71
		opt.minor_no = 71;
		opt.len = 4;
		opt.data = new uint8_t[4];
		tmpi = htons(PXE_SERVER_TYPE);
		memcpy(opt.data, &tmpi, 2);
		opt.data[2] = 0;
		req_layer = opt.data[3] = config->GetMinLayer(arch_id, menu_id);
		AddOption(&opt);
		delete [] opt.data;

	}
	else
	// PXE layer request
	{
		arch_id = reqCSA;

		// get option 71 fromthe request packet
		optptr = request(43, 71);
		menu_id = optptr->data[0];
		menu_id <<= 8;
		menu_id |= optptr->data[1];
		// don't worry about the third byte, it is for 'credentials'
		req_layer = optptr->data[3];

		// make the reply option
		opt.minor_no = 71;
		opt.len = 4;
		opt.data = new uint8_t[opt.len];
		memcpy(opt.data, optptr->data, 2);
		opt.data[2] = 0;

		delete [] optptr->data;
		delete optptr;
		// which layer to get next/any
		if(config->CheckLayer(menu_id, arch_id, req_layer) == 0)
		{
			opt.data[3] = req_layer;
		}
		else
		{
			delete [] opt.data;
			return(-1);
		}
		AddOption(&opt);
		delete [] opt.data;
	}

	// make filename
	tmpc = config->MakeFilename(menu_id, arch_id, req_layer);
	if(strlen(tmpc) > 127) // gotta think of a better way
		tmpi =  127;
	else
		tmpi = strlen(tmpc);

	memcpy(file, tmpc, tmpi);
	file[tmpi] = 0;
	delete [] tmpc;

	// cool, send the reply
	return(0);
}


/******************************************************************************
 * GenOpt54 - generate reply options                                          *
 ******************************************************************************/
int
PacketStore::GenOpt54(void)
{
	option opt;

	opt.len = sizeof(siaddr.s_addr);

	opt.major_no = 54;
	opt.minor_no = 0;
	opt.data = new uint8_t[opt.len];
	memcpy(opt.data, &(siaddr.s_addr), opt.len);
	AddOption(&opt);
	delete [] opt.data;
	return(0);
}


/******************************************************************************
 * GenOpt60 - generate reply options                                          *
 ******************************************************************************/
int
PacketStore::GenOpt60(void)
{
	option opt;
	opt.major_no=60;
	opt.minor_no=0;
	opt.len = strlen(DHCP_T60);
	opt.data = new uint8_t[opt.len];
	memcpy(opt.data, DHCP_T60, opt.len);
	AddOption(&opt);
	delete [] opt.data;
	return(0);
}


/******************************************************************************
 * GetCSA - get the Client System Archetecture of the packet                  *
 ******************************************************************************/
uint16_t
PacketStore::GetCSA(void)
{
	uint16_t csa1, csa2;
	option *opt;
	char csac[6];
	int csa1_nok=0;
	int csa2_nok=0;

	// should have received two copies of the csa, compare
	csa1 = csa2 = 0;

	// the binary packed copy
	opt = GetOption(93);
	if(NULL == opt)
		csa1_nok = 1;
	else
	{
		memcpy(&csa1, opt->data, 2);
		csa1 = ntohs(csa1);
		delete [] opt->data;
		delete opt;
	}

	// get the ascii packed version
	opt = GetOption(60);
	if(NULL == opt)
		csa2_nok = 1;
	else if(32 != opt->len) {
		csa2_nok = 1;
		delete [] opt->data;
		delete opt;
	} else {
		memcpy(csac, opt->data+15, 5);
		csac[5] = 0;
		csa2 = atoi(csac);
		delete [] opt->data;
		delete opt;
	}

	// check details
	if((0 == csa1_nok) && (0 == csa2_nok ) && (csa1 == csa2))
		return(checkCSA(csa1));
	else if ((1 == csa1_nok) && (0 == csa2_nok ))
		return(checkCSA(csa2));
	else if ((0 == csa1_nok) && (1 == csa2_nok ))
		return(checkCSA(csa1));
	
	return((uint16_t)-1);
}


/******************************************************************************
 * checkCSA - see if we are supporting the type of arch                       *
 ******************************************************************************/
uint16_t
PacketStore::checkCSA(uint16_t reqCSA)
{
	int i;
	for(i=0; (uint16_t)-1 != CSA_types[i].arch_id; i++)
		if(CSA_types[i].arch_id == reqCSA)
			break;

	return(CSA_types[i].arch_id);
}


/******************************************************************************
 * MakeReply - pack the packet into a raw data form                           *
 ******************************************************************************/
bootp_packet_t *
PacketStore::PackPacket(void)
{
	int pktlen, pos, len43;
	option *optptr;
	bootp_packet_t *opt = new bootp_packet_t;

	// first go through the packet and see how big it is
	pktlen = 241; // 255 closing tag
	optptr = head;
	while(NULL != optptr)
	{
		pktlen += optptr->len+2; // <tag>,<len>,<data>
		optptr = optptr->next;
	}
	optptr = head43;
	if(NULL != optptr)
		pktlen += 3; // 43,<len>,...,255
	len43 = 0;
	while(NULL != optptr)
	{
		
		pktlen += optptr->len+2; // <tag>,<len>,<data>
		len43 = pktlen;
		optptr = optptr->next;
	}
	
	// initalise
	opt->data = new uint8_t[pktlen];
	pos = 0;

	// basic packet info
	opt->data[0] = op;
	opt->data[1] = htype;
	opt->data[2] = hlen;
	opt->data[3] = hops;
	memcpy(opt->data+4, &xid, 4);
	memcpy(opt->data+8, &secs, 2);
	memset(opt->data+10, 0, 2);

	// the addresses
	memcpy(opt->data+12, &(ciaddr.s_addr), 4);
	memcpy(opt->data+16, &(yiaddr.s_addr), 4);
	memcpy(opt->data+20, &(siaddr.s_addr), 4);
	memcpy(opt->data+24, &(giaddr.s_addr), 4);

	// hardware addr
	memcpy(opt->data+28, chaddr, 16);
	// server name
	memcpy(opt->data+44, sname, 64);
	// filename
	memcpy(opt->data+108, file, 128);

	// magic cookie
	memcpy(opt->data+236, &magic_cookie, 4);

	// basic options
	pos = 240;
	optptr = head;
	while(NULL != optptr)
	{
		opt->data[pos] = optptr->major_no;
		opt->data[pos+1] = optptr->len;
		memcpy(opt->data+pos+2, optptr->data, optptr->len);
		pos += optptr->len+2;
		optptr = optptr->next;
	}
	// option 43
	optptr = head43;
	if(NULL != optptr)
	{
		opt->data[pos] = 43;
		opt->data[pos+1] = len43;
		pos+=2;
	}
	while(NULL != optptr)
	{
		opt->data[pos] = optptr->minor_no;
		opt->data[pos+1] = optptr->len;
		memcpy(opt->data+pos+2, optptr->data, optptr->len);
		pos += optptr->len+2;
		optptr = optptr->next;
	}
	if(NULL != head43)
	{
		opt->data[pos] = 255;
		pos++;
	}

	// close the packet off
	opt->data[pos] = 255;
	opt->len=pos;

	return(opt);
}
