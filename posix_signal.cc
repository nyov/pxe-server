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
 * posix_signal.cc - a nice posix abstraction for a horrible subject          *
 ******************************************************************************/

#include "posix_signal.h"


/******************************************************************************
 * Constructor                                                                *
 ******************************************************************************/
Signal::Signal(LogFile *_log)
{
	this->log = _log;
}


/******************************************************************************
 * Destructor                                                                 *
 ******************************************************************************/
Signal::~Signal()
{
}


/******************************************************************************
 * Set - set a signal register                                                *
 ******************************************************************************/
int
Signal::Set(int SIGNAL, void (*ACTION) (int))
{
	struct sigaction act;

	/* declare what is going to be called when */
	act.sa_handler = ACTION;

	/* clear the structure's mask */
	sigemptyset(&act.sa_mask);

	/* set up some flags */
	act.sa_flags = SA_NOCLDSTOP;
	act.sa_flags &= ~SA_RESTART;

	/* set the signal handler */
	if(sigaction(SIGNAL, &act, NULL) < 0)
		log->Event(LEVEL_ERR, "Signal::Set:sigaction()", 1,
			strerror(errno));

	/* all ok */
	return(0);
}


/******************************************************************************
 * Block - block a signal                                                     *
 ******************************************************************************/
int
Signal::Block(int SIGNAL)
{
	sigset_t set;

	/* initalise */
	sigemptyset(&set);

	/* add the SIGNAL to the set */
	sigaddset(&set, SIGNAL);

	/* block it */
	if(sigprocmask(SIG_BLOCK, &set, NULL) < 0)
		log->Event(LEVEL_ERR, "Signal::Block:sigprocmask()", 1,
			strerror(errno));

	/* done */
	return(0);
}


/******************************************************************************
 * UnBlock - unblock a signal                                                 *
 ******************************************************************************/
int
Signal::UnBlock(int SIGNAL)
{
	sigset_t set;

	/* initalise */
	sigemptyset(&set);

	/* add the SIGNAL to the set */
	sigaddset(&set, SIGNAL);

	/* block it */
	if(sigprocmask(SIG_UNBLOCK, &set, NULL) < 0)
		log->Event(LEVEL_ERR, "Signal::UnBlock:sigprocmask()", 1,
			strerror(errno));

	/* done */
	return(0);
}
