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
 * logfile.c - a sereis of general event logging procedures                   *
 ******************************************************************************/

#include "logfile.h"

/******************************************************************************
 * LogFile - constructor                                                      *
 ******************************************************************************/
LogFile::LogFile()
{
	Open(PXELOGFILE);
}


/******************************************************************************
 * LogFile - constructor                                                      *
 ******************************************************************************/
LogFile::LogFile(const char *filename)
{
	Open(filename);
}


/******************************************************************************
 * LogFile - constructor                                                      *
 ******************************************************************************/
LogFile::~LogFile()
{
	Close();
}


/******************************************************************************
 * LogOpen - open a log file or die and exit painfully                        *
 ******************************************************************************/
void
LogFile::Open(const char *filename)
{
	/* open the file */
	umask(077);
	logfile = new std::fstream(filename, std::ios::out|std::ios::app);
	if(logfile == NULL)
	{
		std::cerr << "Error: LogFile::Open:open(): " << strerror(errno) <<"\n";
		exit(-1);
	}
}


/******************************************************************************
 * LogClose - close the active lof file                                       *
 ******************************************************************************/
void
LogFile::Close(void)
{
	logfile->flush();
	logfile->close();
}

/******************************************************************************
 * LogEvent - log an event into the logfile                                   *
 ******************************************************************************/
void
LogFile::Event(int level, const char *where, int count, ...)
{
	time_t currsecs;
	char *timestr;
	const char *error;
	int len;
	va_list argp;
	char *p;
	
	/* format date and message etc */
	currsecs = time(0);
	timestr = asctime(localtime(&currsecs));
	len = strlen(timestr);
	timestr[len-1] = ':';
	switch(level)
	{
	case 1:
		error = LEVEL_INFO_C;
		break;
	case 2:
		error = LEVEL_ERR_C;
		break;
	case 3:
		error = LEVEL_EMRG_C;
		break;
	case 4:
		error = LEVEL_FATAL_C;
		break;
	default:
		error = " Unknown: ";
		break;
	}

	/* write info */
	*logfile << timestr << " " << error << " " << where << ": ";

	/* send any extra args */
	va_start(argp, count);
	for(len = 0; len < count; len++)
	{
		p = va_arg(argp, char *);
		*logfile << p << " ";
	}
	va_end(argp);

	*logfile << "\n";
	logfile->flush();
}
