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
 * pxe.c - a pxe server, made better than intel's hack                        *
 ******************************************************************************/

#include <sys/types.h>
#include <iostream>
#include <fstream>

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <signal.h>
#include <sys/signal.h>
#include <unistd.h>
#include <pwd.h>

#include "sock.h"
#include "logfile.h"
#include "packetstore.h"
#include "options.h"
#include "sysexception.h"
#include "posix_signal.h"
#include "autoconf.h"

int service_requests=1;
int watchchld = 1;

#define BUFFER_SZ 2048

/*
 * can only bind to one address, otherwise multicast is inherently
 * messed up. There were big problems with the multicast address
 * as it can only send multicast when bound to 0.0.0.0
 */

/******************************************************************************
 * Usage - show the usage and exit                                            *
 ******************************************************************************/
void Usage(char *progname)
{
	std::cerr << "Usage: " << progname << " [-c <configfile>] [-d]\n";
	std::cerr << "Tim Hurman (kano@kano.org.uk) " << __DATE__ << "\n";
	exit(1);
}


/******************************************************************************
 * HandleSig - handle some standard signals                                   *
 ******************************************************************************/
void HandleSig(int signo)
{
	service_requests=0;
}


/******************************************************************************
 * HandleSigChld - handle the death of a child                                *
 ******************************************************************************/
void HandleSigChld(int signo)
{
	int status;

	while(waitpid(-1, &status, WNOHANG) > 0)
		watchchld = 0;
}


/******************************************************************************
 * StartPxeService - service incoming pxe requests                            *
 ******************************************************************************/
int StartPxeService(const char *configfile)
{
	LogFile logger;
	Options *opts = NULL;
	Sock *connection = NULL;
	Signal sig(&logger);
	PacketStore request(&logger);
	PacketStore reply(&logger);
	PacketStore test(&logger);
	int retval = 0;
	extern char *optarg;
	int recvlen;
	char *buf;
	struct sockaddr_in server_addr, client_addr;
	bootp_packet_t *pkt;

	// register some signal handlers
	sig.Set(SIGINT, HandleSig);
	sig.Set(SIGTERM, HandleSig);
	sig.Set(SIGHUP, (void(*)(int))SIG_IGN);

	// assign memory
	buf = new char[BUFFER_SZ];

	// read the config file
	std::cout << "Opening " << configfile << "\n";

	try {
		opts = new Options(&logger, configfile);
	} catch (SysException *e) {
		std::cerr << "An error occurred, please check the logfile\n";
		if(e->HaveMessage())
			logger.Event(LEVEL_FATAL, e->GetWhere(), 1, e->GetMessage());
		else
			logger.Event(LEVEL_FATAL, e->GetWhere(), 1, strerror(e->GetErrno()));
		delete e;
		retval = 1;
		goto MainCleanup;
	}

	// open the socket
	try {
		connection = new Sock(&logger, opts->GetInterface(), opts->GetPort());
		connection->SetDefAddr(opts->GetDefAddr());
	
		if(opts->UseBroadcast())
			connection->AllowBroadcast();

		if(opts->UseMulticast())
			connection->JoinMulticast(opts->GetMulticast());

	} catch (SysException *e) {
		std::cerr << "An error occurred, please check the logfile\n";
		if(e->HaveMessage())
			logger.Event(LEVEL_FATAL, e->GetWhere(), 1, e->GetMessage());
		else
			logger.Event(LEVEL_FATAL, e->GetWhere(), 1, strerror(e->GetErrno()));
		delete e;
		retval = 1;
		goto MainCleanup;
	}
	
	// receive packets
	while(service_requests)
	{
		try {
			// blank the reply socket
			reply.Initalise();
			request.Initalise();

			// need try statement
			recvlen = connection->Read((unsigned char*)buf, BUFFER_SZ,
			  &client_addr, &server_addr);
		
			if(recvlen <= 0)
				goto service_requests_next;

			// parse the request
			request.ReadPacket((unsigned char*)buf, recvlen);
			request.SetAddress(&client_addr);
			std::cout << "\n---Request---\n" << request << "\n";

			if(reply.MakeReply(request, opts, &server_addr) == -1)
				goto service_requests_next;

			// print the packet
			std::cout  << "\n---Reply---\n\n" << reply << "\n";
			pkt = reply.PackPacket();

			// send the packet back to the client
			connection->Send((unsigned char*)pkt->data, pkt->len,
			  &client_addr, &server_addr);

			delete [] pkt->data;
			delete pkt;

			service_requests_next:
			recvlen=recvlen;
		} catch (SysException *e) {
			std::cerr << "An error occurred, please check the logfile\n";
			if(e->HaveMessage())
				logger.Event(LEVEL_FATAL, e->GetWhere(), 1, e->GetMessage());
			else
				logger.Event(LEVEL_FATAL, e->GetWhere(), 1,
				  strerror(e->GetErrno()));
			delete e;
			retval = 1;
		}
	}

	// tidy up and exit
	MainCleanup:
	if(opts != NULL)
		delete opts;
	if(connection != NULL)
		delete connection;
	delete[] buf;
	unlink(LOCKFILE);
	return(retval);
}


/******************************************************************************
 * main - kick things off and do cool things                                  *
 ******************************************************************************/
int main(int argc, char **argv)
{
	int chk;
	char pidnum[8];
	int _debug, c, errflg;
	const char *configfile=PXECONFIGFILE;
	std::fstream debug;

	errflg = _debug = 0;
	// get the command line opts
	while ((c = getopt(argc, argv, "dc:")) != EOF)
		switch(c)
		{
		case 'c':
			configfile = optarg;
			break;
		case 'd':
			_debug = 1;
			break;
		default:
			errflg++;
		}

	// errors?
	if(errflg)
		Usage(argv[0]);

	// check the config file exists
	debug.open(configfile, std::ios::in);
	if (!debug.is_open()) {
		std::cerr << "Unable to open the config file\n";
		exit (1);
	}
	debug.close();

	// redirect the file descriptors
	if (0 == _debug) {
		debug.open("/dev/null", std::ios::out);
		std::cout.rdbuf(debug.rdbuf());
		std::cerr.rdbuf(debug.rdbuf());
		debug.close();
		debug.open("/dev/zero", std::ios::in);
		std::cin.rdbuf(debug.rdbuf());
		debug.close();
	}


	// set the UID/GID to a low user
#ifndef NO_SUID
	struct passwd *pw;
	pw = getpwnam(SETUID);

	if(NULL == pw)
		std::cout << "Unable to find passwd entry for " << SETUID
		     << ", continuing with user id " << getuid() << "\n";
	else
	{
		if((-1 == setgid(pw->pw_gid)) || (-1 == setegid(pw->pw_gid)))
			std::cout << "Unable to change group id, continuing with group id "
			     << getgid() << "\n";
		if((-1 == setuid(pw->pw_uid)) || (-1 == seteuid(pw->pw_uid)))
			std::cout << "Unable to change user id, continuing with user id "
			     << getuid() << "\n";
	}
#endif

	// check to see if the daemon is already running
	chk = open(LOCKFILE, O_WRONLY|O_CREAT|O_EXCL, 0644);
	if(-1 == chk)
	{
		std::cerr << "PXE daemon already running\n";
		return(-1);
	}

	// if not in debug mode, fork and go
	if (0 == _debug) {
		signal(SIGCHLD, SIG_IGN);

		// set up the daemon
		switch (fork()) {
		case -1:
			std::cerr << "Unable to fork child\n";
			exit(-1);
		case 0:
			// become the process group session leader
			setsid();

			// the second fork
			switch(fork()) {
			case -1:
				std::cerr << "Unable to fork child\n";
				exit(-1);
			case 0:
				// change the working dir
				chdir("/");

				// clear the mask
				umask(0);

				// write out the pid
				sprintf(pidnum, "%ld", (long)getpid());
				if(write(chk, pidnum, strlen(pidnum)) !=
				  (ssize_t)strlen(pidnum)) {
					std::cerr << "Unable to write lockfile\n";
					exit(-1);
				}
				close(chk);

				StartPxeService(configfile);

				exit(0);
			}
			exit(0);
		}

	} else { // debug
		StartPxeService(configfile);
	}
	
	return(0);
}
