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
 * posix_signal.h - a nice posix abstraction for a horrible subject           *
 ******************************************************************************/


#ifndef _POSIX_SIGNAL_H
#define _POSIX_SIGNAL_H

#include <sys/types.h>
#include <sys/wait.h>   /* header for waitpid() and various macros */
#include <signal.h>     /* header for signal functions */
#include <stdio.h>      /* header for fprintf() */
#include <stdlib.h>      /* header for fprintf() */
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include "logfile.h"
#include "config.h"

class Signal
{
	private:
		LogFile *log;

	public:
		Signal(LogFile *log);
		~Signal();

		int Set(int SIGNAL, __sighandler_t ACTION);
		int Block(int SIGNAL);
		int UnBlock(int SIGNAL);

};

#endif //_POSIX_SIGNAL_H
