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
 * config.h - pxe daemon configuration files                                  *
 ******************************************************************************/

#ifndef _CONFIG_H
#define _CONFIG_H

#define SETUID "nobody"
#define LOCKFILE "/tmp/pxe.pid"

#define PXELOGFILE "/tmp/pxe.log"
#define PXECONFIGFILE "/etc/pxe.conf"

#define DEF_MULTI_BOOT 0xe0000102
#define DEF_ADDR "0.0.0.0"
#define DEF_PORT 4011

#define BOOTPC_NAME "bootpc"

#define PXE_SERVER_TYPE 0 // PXE bootstrap server

#define DHCP_T60 "PXEClient"

#define DEF_MTFTP_ADDR 0xe0010501
#define DEF_MTFTP_CPORT 0x06de
#define DEF_MTFTP_SPORT 0x06df
#define MTFTP_OPEN_TIMEOUT 1  // secs before fail
#define MTFTP_REOPEN_TIMEOUT 2  // secs before retrying

#define DEF_DOMAIN "example.net"
#define TFTPD_BASE "/tftpboot"
#define DEF_PROMPT "Press F8 to view menu ..."
#define DEF_PROMPT_TIMEOUT 10

#ifdef SOLARIS
#define __sighandler_t SIG_PF // solaris compatability
#endif // __sighandler_t

// this is used in lots of places, so it's going here
struct _option
{
	uint8_t major_no;
	uint8_t minor_no;
	uint8_t len;
	uint8_t *data;
	struct _option *next;
};
typedef struct _option option;

// packet store
struct bootp_packet
{
	int len;
	uint8_t *data;
};
typedef struct bootp_packet bootp_packet_t;


#endif // _CONFIG_H
