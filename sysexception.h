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
 * sysexception.h - exceptions class for pxe daemon                           *
 ******************************************************************************/


#ifndef _SYSEXCEPTION_H
#define _SYSEXCEPTION_H

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

class SysException
{
	private:
		int local_errno;
		char *loc;
		char *mess;

	public:
		SysException(const int err, const char *loc);
		SysException(const int err, const char *loc, const char *message);
		~SysException();

		int HaveMessage();
		char *GetWhere();
		char *GetMessage();
		int GetErrno();


};

#endif
