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
 * options.h - read the config options from the file                          *
 ******************************************************************************/


#ifndef _OPTIONS_H
#define _OPTIONS_H

#include <sys/types.h>
#include <stdio.h>
#include <iostream.h>
#include <fstream.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "sysexception.h"
#include "logfile.h"
#include "config.h"

struct _services
{
	int csa;
	uint8_t min_level;
	uint8_t max_level;
	uint16_t menu_id;
	char *filebase;
	char *menu_text;
	struct _services *next;
};
typedef struct _services services_t;

struct _CSA
{
	uint16_t arch_id;
	char *arch_name;
};
typedef struct _CSA CSA_t;

#define CSA_MAX_TYPES 7
extern CSA_t CSA_types[CSA_MAX_TYPES];


class Options
{
	private:
		char *interface;
		char *prompt;
		uint8_t prompt_timeout;
		uint32_t multicast_address;
		char *domain;
		char *tftpdbase;
		uint16_t port;
		unsigned char use_multicast;
		unsigned char use_broadcast;
		services_t *serv_head;
		uint16_t mtftp_cport;
		uint16_t mtftp_sport;
		uint32_t mtftp_address;
		uint32_t default_address;

		LogFile *log;

	public:
		Options(LogFile *);
		Options(LogFile *, const char *);
		~Options();

		char *GetInterface();
		uint16_t GetPort();
		int UseMulticast();
		int UseBroadcast();
		uint32_t GetMulticast();
		uint32_t GetMTFTPAddr();
		uint16_t GetMTFTPsport();
		uint16_t GetMTFTPcport();
		uint32_t GetDefAddr();
		uint8_t GetMenuTimeout();
		char *GetMenuPrompt();
		uint16_t CheckMenu(uint16_t);
		option *MakeBootMenu(int, int *, int *);
		uint8_t GetMinLayer(int, int);
		uint8_t GetMaxLayer(int, int);
		char *MakeFilename(int, int, uint8_t);
		int CheckLayer(int, int, uint8_t);

	private:
		void ReadFile(const char *);
		void AddService(char *, int *);
	
};


#endif
