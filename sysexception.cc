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
 * sysexception.cc - exceptions class for pxe daemon                          *
 ******************************************************************************/

#include "sysexception.h"


/******************************************************************************
 * SysException - constructor for exception                                   *
 ******************************************************************************/
SysException::SysException(const int err, const char *location)
{
	local_errno = err;
	loc = new char[strlen(location)+1];
	strcpy(loc, location);
	mess = NULL;
}


/******************************************************************************
 * SysException - constructor for exception                                   *
 ******************************************************************************/
SysException::SysException(const int err, const char *location,
	const char *message)
{
	local_errno = err;
	loc = new char[strlen(location)+1];
	strcpy(loc, location);
	mess = new char[strlen(message)+1];
	strcpy(mess, message);
}


/******************************************************************************
 * SysException - deconstuctor for exception                                  *
 ******************************************************************************/
SysException::~SysException()
{
	local_errno = 0;
	delete[] loc;
	
	if(mess != NULL)
		delete[] mess;
}


/******************************************************************************
 * HaveMessage - check is a message is present                                *
 ******************************************************************************/
int
SysException::HaveMessage()
{
	if(mess != NULL)
		return(1);
	else
		return(0);
}


/******************************************************************************
 * GetWhere - return where the exception occurred                             *
 ******************************************************************************/
char *
SysException::GetWhere()
{
	return(loc);
}


/******************************************************************************
 * GetMessage - return the message (if any)                                   *
 ******************************************************************************/
char *
SysException::GetMessage()
{
	return(mess);
}


/******************************************************************************
 * GetErrno - return the errno that occurred                                  *
 ******************************************************************************/
int
SysException::GetErrno()
{
	return(local_errno);
}
