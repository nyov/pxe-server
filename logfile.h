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
 * logfile.h - a sereis of general event logging procedures                   *
 ******************************************************************************/

#ifndef _LOGFILE_H
#define _LOGFILE_H

#include <sys/types.h>
#include <stdio.h>
#include <stream.h>
#include <fstream.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>

#ifdef LINUX
#include <stdint.h>
#endif // LINUX

#include "config.h"

#define LEVEL_INFO_C "Info:"
#define LEVEL_ERR_C "Error:"
#define LEVEL_EMRG_C "Emergency:"
#define LEVEL_FATAL_C "Fatal:"

#define LEVEL_INFO 1
#define LEVEL_ERR 2
#define LEVEL_EMRG 3
#define LEVEL_FATAL 4

class LogFile
{
	private:
		fstream *logfile;

	public:
		LogFile();
		LogFile(const char *filename);
		~LogFile();
		void Event(int level, const char *where, int count, ...);

	private:
		void Open(const char *filename);
		void Close(void);
};

#endif
