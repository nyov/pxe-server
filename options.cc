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
 * options.cc - read the config options from the file                         *
 ******************************************************************************/


#include "options.h"

// global vars 
CSA_t CSA_types[CSA_MAX_TYPES] =
{
	{0, "X86PC"},
	{1, "PC98"},
	{2, "IA64PC"},
	{3, "DEC"},
	{4, "ArcX86"},
	{5, "ILC"},
	{(uint16_t)-1, NULL}
};



/******************************************************************************
 * Options - constructor - read from the default file                         *
 ******************************************************************************/
Options::Options(LogFile *_log)
{
	this->log = _log;
	ReadFile(PXECONFIGFILE);
}


/******************************************************************************
 * Options - constructor - read from the specified file                       *
 ******************************************************************************/
Options::Options(LogFile *_log, const char *filename)
{
	this->log = _log;
	ReadFile(filename);
}


/******************************************************************************
 * Options - Deconstuctor                                                     *
 ******************************************************************************/
Options::~Options()
{
	services_t *serv_ptr, *serv_prev;

	if(interface != NULL)
		delete[] interface;
	if(prompt != NULL)
		delete[] prompt;
	if(domain != NULL)
		delete[] domain;
	if(tftpdbase != NULL)
		delete[] tftpdbase;
	port = 0;

	// scan and delete options
	for(serv_ptr=serv_prev=serv_head; serv_ptr != NULL; )
	{
		serv_prev = serv_ptr;
		serv_ptr = serv_ptr->next;
		delete[] serv_prev->filebase;
		delete[] serv_prev->menu_text;
		delete serv_prev;
	}

	serv_head = NULL;

}


/******************************************************************************
 * ReadFile - read the config file                                            *
 ******************************************************************************/
void
Options::ReadFile(const char *filename)
{
	std::fstream *fp;
	int len;
	char *key,*val;
	struct in_addr t_addr;
	int key_id = 1;
	char *buf;

	// initalise vars
	buf = new char[1024];
	tftpdbase = (char*)TFTPD_BASE;
	domain = (char*)DEF_DOMAIN;
	interface = NULL;
	prompt = (char*)DEF_PROMPT;
	
	multicast_address = DEF_MULTI_BOOT;
	mtftp_address = DEF_MTFTP_ADDR;
	mtftp_cport = DEF_MTFTP_CPORT;
	mtftp_sport = DEF_MTFTP_SPORT;
	port = DEF_PORT;
	prompt_timeout = DEF_PROMPT_TIMEOUT;
	default_address = 0;

	use_multicast = use_broadcast = 1;
	serv_head = NULL;

	fp = new std::fstream(filename, std::ios::in);
	if(fp == NULL)
		throw new SysException(errno, "Options::ReadFile:fopen()");
	
	while(fp->getline(buf, 1024))
	{
		len = strlen(buf)-1;

		if(-1 == len) goto Options_ReadFile_next;

		for(; len > 0; len--)
			if((buf[len] != '\n') && (buf[len] != '\r'))
			{
				len++;
				break;
			}
		
		buf[len] = 0;
		
		
		if((buf[0] == ' ') || (buf[0] == '#') || (buf[0] == 0))
			goto Options_ReadFile_next;

		// examine the string contents
		key = strtok(buf, "=");
		if(key == NULL)
			goto Options_ReadFile_next;

		val = strtok(NULL, "=");
		if(val == NULL)
			goto Options_ReadFile_next;

		// examine key
		if(strcmp("interface", key) == 0)
		{
			interface = new(char[strlen(val)+1]);
			strcpy(interface, val);
		}
		else if(strcmp("prompt", key) == 0)
		{
			prompt = new(char[strlen(val)+1]);
			strcpy(prompt, val);
		}
		else if(strcmp("listen_port", key) == 0)
		{
			port = atoi(val);
		}
		else if(strcmp("use_multicast", key) == 0)
		{
			use_multicast = atoi(val);
		}
		else if(strcmp("use_broadcast", key) == 0)
		{
			use_broadcast = atoi(val);
		}
		else if(strcmp("multicast_address", key) == 0)
		{
			t_addr.s_addr = 0;
#ifdef HAVE_INET_ATON
			if(0 == inet_aton(val, &t_addr))
#else
			t_addr.s_addr = inet_addr(val);
			if((unsigned)-1 == t_addr.s_addr)
#endif // HAVE_INET_ATON
				t_addr.s_addr = DEF_MTFTP_ADDR;
			multicast_address = ntohl(t_addr.s_addr);
		}
		else if(strcmp("domain", key) == 0)
		{
			domain = new(char[strlen(val)+1]);
			strcpy(domain, val);
		}
		else if(strcmp("tftpdbase", key) == 0)
		{
			tftpdbase = new(char[strlen(val)+1]);
			strcpy(tftpdbase, val);
		}
		else if(strcmp("service", key) == 0)
		{
			AddService(val, &key_id);
		}
		else if(strcmp("mtftp_address", key) == 0)
		{
			t_addr.s_addr = 0;
#ifdef HAVE_INET_ATON
			if(0 == inet_aton(val, &t_addr))
#else
			t_addr.s_addr = inet_addr(val);
			if((unsigned)-1 == t_addr.s_addr)
#endif // HAVE_INET_ATON
				t_addr.s_addr = htonl(DEF_MTFTP_ADDR);
			mtftp_address = ntohl(t_addr.s_addr);
		}
		else if(strcmp("mtftp_client_port", key) == 0)
		{
			mtftp_cport = atoi(val);
			if(mtftp_cport == 0) mtftp_cport = DEF_MTFTP_CPORT;
		}
		else if(strcmp("mtftp_server_port", key) == 0)
		{
			mtftp_sport = atoi(val);
			if(mtftp_sport == 0) mtftp_sport = DEF_MTFTP_SPORT;
		}
		else if(strcmp("prompt_timeout", key) == 0)
		{
			prompt_timeout = atoi(val);
			if((0 == prompt_timeout) && (EINVAL == errno))
				prompt_timeout = DEF_PROMPT_TIMEOUT;
		}
		else if(strcmp("default_address", key) == 0)
		{
			t_addr.s_addr = 0;
#ifdef HAVE_INET_ATON
			if(0 == inet_aton(val, &t_addr))
#else
			t_addr.s_addr = inet_addr(val);
			if((unsigned)-1 == t_addr.s_addr)
#endif // HAVE_INET_ATON
				t_addr.s_addr = DEF_MTFTP_ADDR;
			default_address = ntohl(t_addr.s_addr);
		}
		else
		{
			log->Event(LEVEL_ERR, "Options::ReadFile", 2,
				"Unknown key:", key);
		}
	
		Options_ReadFile_next:
		fp = fp;
	}

	fp->close();
	delete[] buf;
}


/******************************************************************************
 * GetInterface - get the interface name                                      *
 ******************************************************************************/
char *
Options::GetInterface()
{
	return(interface);
}


/******************************************************************************
 * GetPort - return the port number                                           *
 ******************************************************************************/
uint16_t
Options::GetPort()
{
	return(port);
}


/******************************************************************************
 * UseMulticast - shall we use multicast discovery                            *
 ******************************************************************************/
int
Options::UseMulticast()
{
	return(use_multicast);
}


/******************************************************************************
 * UseBroadcast - shall we use broadcast discovery                            *
 ******************************************************************************/
int
Options::UseBroadcast()
{
	return(use_broadcast);
}


/******************************************************************************
 * GetMulticast - return the multicast address specified                      *
 ******************************************************************************/
uint32_t
Options::GetMulticast()
{
	return(multicast_address);
}


/******************************************************************************
 * AddService - add a service to the list                                     *
 ******************************************************************************/
void
Options::AddService(char *serviceinfo, int *key_id)
{
	services_t *serv_ptr, *serv_tail, *serv_prev;
	char *ptr;
	int i;

	ptr = strtok(serviceinfo, ",");
	if(ptr == NULL)
	{
		log->Event(LEVEL_ERR, "AddService:parse", 1,
		   "Invalid service declaration");
		return;
	}

	// see if it is a recognised CSA
	for(i=0; ((CSA_types[i].arch_name != NULL) &&
	    (strcmp(CSA_types[i].arch_name, ptr) != 0)); i++);

	// valid CSA?
	if(CSA_types[i].arch_name == NULL)
	{
		log->Event(LEVEL_ERR, "AddService:parse", 1,
		   "Unknown client system architecture");
		return;
	}

	// assign the info
	serv_ptr = new services_t;
	serv_ptr->csa = CSA_types[i].arch_id;

	// min layer
	ptr = strtok(NULL, ",");
	if(ptr == NULL)
	{
		log->Event(LEVEL_ERR, "AddService:parse", 1,
		   "Invalid service declaration");
		delete serv_ptr;
		return;
	}
	serv_ptr->min_level = atoi(ptr);
	
	// max layer
	ptr = strtok(NULL, ",");
	if(ptr == NULL)
	{
		log->Event(LEVEL_ERR, "AddService:parse", 1,
		   "Invalid service declaration");
		delete serv_ptr;
		return;
	}
	serv_ptr->max_level = atoi(ptr);

	// basename
	ptr = strtok(NULL, ",");
	if(ptr == NULL)
	{
		log->Event(LEVEL_ERR, "AddService:parse", 1,
		   "Invalid service declaration");
		delete serv_ptr;
		return;
	}
	serv_ptr->filebase = new char[strlen(ptr)+1];
	strcpy(serv_ptr->filebase, ptr);

	// menu entry
	ptr = strtok(NULL, "\0");
	if(ptr == NULL)
	{
		log->Event(LEVEL_ERR, "AddService:parse", 1,
		   "Invalid service declaration");
		delete[] serv_ptr->filebase;
		delete serv_ptr;
		return;
	}
	if(strlen(ptr) > 255)
	{
		log->Event(LEVEL_ERR, "AddService:parse", 1,
			"Menu item too long");
		delete[] serv_ptr->filebase;
		delete serv_ptr;
		return;
	}
	serv_ptr->menu_text = new char[strlen(ptr)+1];
	strcpy(serv_ptr->menu_text, ptr);
	if(strcmp(serv_ptr->filebase, "local") == 0)
		serv_ptr->menu_id = 0;
	else
	{
		serv_ptr->menu_id = *key_id;
		(*key_id)++;
	}

	// find the tail of the list
	for(serv_prev=serv_tail=serv_head; serv_tail != NULL;
	 serv_tail=serv_tail->next)
		serv_prev = serv_tail;

	// append + sort out minor faults
	if(serv_tail == serv_prev) // on head
		serv_head = serv_ptr;
	else
		serv_prev->next = serv_ptr;

	// end of list
	serv_ptr->next = NULL;
}


/******************************************************************************
 * GetMTFTPAddr - return the multicast address of the mtftp daemon            *
 ******************************************************************************/
uint32_t
Options::GetMTFTPAddr()
{
	return(mtftp_address);
}


/******************************************************************************
 * GetMTFTPAddr - return the multicast address of the mtftp daemon            *
 ******************************************************************************/
uint32_t
Options::GetDefAddr()
{
	return(default_address);
}


/******************************************************************************
 * GetMTFTPsport - return the multicast server port of the mtftp daemon       *
 ******************************************************************************/
uint16_t
Options::GetMTFTPsport()
{
	return(mtftp_sport);
}


/******************************************************************************
 * GetMTFTPcport - return the multicast client port of the mtftp daemon       *
 ******************************************************************************/
uint16_t
Options::GetMTFTPcport()
{
	return(mtftp_cport);
}


/******************************************************************************
 * GetMenuTimeout - return the amount of time the boot menu is shown for      *
 ******************************************************************************/
uint8_t
Options::GetMenuTimeout()
{
	return(prompt_timeout);
}


/******************************************************************************
 * GetMenuPrompt - return the menu string                                     *
 ******************************************************************************/
char *
Options::GetMenuPrompt()
{
	char *c = new char[strlen(prompt)+1];
	strcpy(c, prompt);
	return(c);
}


/******************************************************************************
 * CheckMenu - check to see if there is a menu item for a specific CSA        *
 ******************************************************************************/
uint16_t
Options::CheckMenu(uint16_t reqcsa)
{
	services_t *serv_ptr;

	serv_ptr = serv_head;
	while(NULL != serv_ptr)
	{
		if(serv_ptr->csa == reqcsa)
			return(serv_ptr->csa);
		serv_ptr = serv_ptr->next;
	}

	return((uint16_t)-1);
}


/******************************************************************************
 * MakeBootMenu - make the option for the boot menu                           *
 ******************************************************************************/
option *
Options::MakeBootMenu(int csa, int *arch_id, int *menu_id)
{
	int i,j;
	uint16_t menu_id_n;
	int count = 0;
	services_t *serv_ptr;
	option *opt = new option;
	opt->len = i = 0;

	// work out how much memory we need
	serv_ptr = serv_head;
	while(NULL != serv_ptr)
	{
		if(serv_ptr->csa == csa)
			opt->len += strlen(serv_ptr->menu_text)+3;
		serv_ptr = serv_ptr->next;
	}

	opt->data = new uint8_t[opt->len];
	
	// copy the menu items
	serv_ptr = serv_head;
	while(NULL != serv_ptr)
	{
		if(serv_ptr->csa == csa)
		{
			menu_id_n = htons(serv_ptr->menu_id);
			memcpy(opt->data+i, &menu_id_n, 2);
			i += 2;

			j = strlen(serv_ptr->menu_text);
			opt->data[i] = j;
			i++;
			memcpy(opt->data+i, serv_ptr->menu_text, j);
			i += j;

			if(0 == count)
			{
				*arch_id = serv_ptr->csa;
				*menu_id = serv_ptr->menu_id;
			}
			count++;
		}
		serv_ptr = serv_ptr->next;
	}
	
	// last check
	if(0 == opt->len)
		return(NULL);
	return(opt);
}


/******************************************************************************
 * GetMinLayer - get the lowest layer for this item                           *
 ******************************************************************************/
uint8_t
Options::GetMinLayer(int arch_id, int menu_id)
{
	services_t *serv_ptr;

	serv_ptr = serv_head;
	while(NULL != serv_ptr)
	{
		if((menu_id == serv_ptr->menu_id) &&
		  (arch_id == serv_ptr->csa))
		  
			break;
		serv_ptr = serv_ptr->next;
	}
	if(NULL == serv_ptr)
		return(0);
	return(serv_ptr->min_level);
}


/******************************************************************************
 * GetMaxLayer - get the highest layer for this item                          *
 ******************************************************************************/
uint8_t
Options::GetMaxLayer(int arch_id, int menu_id)
{
	services_t *serv_ptr;

	serv_ptr = serv_head;
	while(NULL != serv_ptr)
	{
		if((menu_id == serv_ptr->menu_id) &&
		  (arch_id == serv_ptr->csa))
		  
			break;
		serv_ptr = serv_ptr->next;
	}
	if(NULL == serv_ptr)
		return(0);
	return(serv_ptr->max_level);
}


/******************************************************************************
 * MakeFilename - make the boot filename for a specific arch/layer            *
 ******************************************************************************/
char *
Options::MakeFilename(int menu_id, int arch_id, uint8_t layer)
{
	services_t *serv_ptr;
	char *tmpc;
	int i;

	serv_ptr = serv_head;
	while(NULL != serv_ptr)
	{
		if((menu_id == serv_ptr->menu_id) &&
		  (arch_id == serv_ptr->csa))
		  
			break;
		serv_ptr = serv_ptr->next;
	}

	if(NULL == serv_ptr)
		return(NULL);

	if((layer < serv_ptr->min_level) || (serv_ptr->max_level < layer))
		return(NULL);

	// search for the arch name
	for(i=0; i != CSA_types[i].arch_id; i++);
	tmpc = new char[strlen(CSA_types[i].arch_name) +
	  (strlen(serv_ptr->filebase)*2) + 8];
	sprintf(tmpc, "%s/%s/%s.%d", CSA_types[i].arch_name,
	  serv_ptr->filebase, serv_ptr->filebase, layer);

	return(tmpc);
}


/******************************************************************************
 * CheckLayer - see if the layer requested is withing the valid range         *
 ******************************************************************************/
int
Options::CheckLayer(int menu_id, int arch_id, uint8_t layer)
{

	services_t *serv_ptr;

	serv_ptr = serv_head;
	while(NULL != serv_ptr)
	{
		if((menu_id == serv_ptr->menu_id) &&
		  (arch_id == serv_ptr->csa))
		  
			break;
		serv_ptr = serv_ptr->next;
	}
	if(NULL == serv_ptr)
		return(-1);

	if((layer < serv_ptr->min_level) || (serv_ptr->max_level < layer))
		return(-1);

	return(0);
}
