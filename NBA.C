/*

----------------------------------------------------------------------------

        Copyright (C) 1990 Novell, Inc.
	
        This software may be freely copied and distributed, provided the 
        above copyright notice is included. It may not be sold, in whole
        or in part, without the prior written consent of Novell, Inc.

----------------------------------------------------------------------------

        NBA.C  Netbios Broadcast Agent    /BSB

	This is SAMPLE source code, NOT a Novell product, 
        and will not be supported by the technical staff of Novell.

	DESCRIPTION:

	This program provides an example of how to forward name service
  	broadcasts to remote netbios networks connected via gateways or
	routers which do not usually forward such packets.  It is designed
	to be run in either Server mode or Agent mode.
		Server mode requires that this program (NBA) be run on the local
	network. It receives netbios name query broadcasts (status=0x110) and
	replies with a query response (status=0x8500), if the query name and
	internet address entry is found in the HOSTS file.  No reply packet
	is sent if the name is not found in the HOSTS file.
		Agent mode involves running one NBA on the local net, and one on
	the remote network.  The local NBA receives broadcasts on the local
	network, saves pertinent packet information such as client address,
	port, transaction ID, etc., in a control block (header).  The
	packet is then prepended with the NBA header, and then forwarded to
	the remote NBA.  When it is received, the remote NBA strips off
	the header, saves (enqueues) the header, and then the original
	(de-encapsulated) netbios packet is broadcast on the remote network.
	When the remote NBA receive a reply, if at all, to the broadcast,
	the header information is dequeued based on the the transaction id of
	the reply packet.  The destination address, port, and tid of the
 	reply packet is then set to the (client) values stored in the
	dequeued NBA header and the resulting packet is sent (directed) back
	to the the client node which made the original broadcast.
		This forwarding of the broadcast and reply packets, in effect,
	internets the name service.

	FEATURES/LIMITATIONS:

	*	NBA is written to be very portable.  It will run on 680xx
	        and Sparc Unix machines as well as 80286/386 OS2 machines and
		should be easily ported to DOS.

	*	This program makes extensive use of the HOSTS file.
		Entries must exist for BROADCAST, LOCALHOST, as well
		as any names requiring a response when running NBA in
		server mode.  If subnetting is in use on the network
		the BROADCAST address of the form WW.YY.0xff.0xff may
		not work on some BSD implementations.  In this case an
		appropriate subnet broadcast address should be used.
		A subnet broadcast address has the form:

         WW.XX.YY.ZZ   where

         WW.XX = the network portion address
            ZZ = the host portion address (all set)
            YY = for a node with a subnet mask of 0xfc, this
                 defines the upper 6 bits of the byte as the subnet
                 portion (set to the subnet value) and the lower
                 2 bits (both set) as part of the host portion.

         example:      subnet mask = 0xfc
                       network     = 0x82.0x39
                       broadcast on subnet 1 = 0x82.0x39.0x07.0xff

	*	In order to run NBA (port 137) on Unix requires	super-user privilige 
		The port value should only be changed during testing, and
		should always be 137 as this is the UDP name service port.

	*       When running NBA in server mode, entries in the HOSTS file
	        should be in upper case.

	*	Although an agent may receive NBA packets from any number
		of remote NBA agents, it will only forward broadcasts to one remote
		NBA agent.  In other words, an NBA will not simultaneously forward
		a packet to multiple remote NBA's.  This can be accomplished by
		running multiple NBA's on the local net (on different machines)
		each of which will receive broadcasts, but forward the packets to
		different remote agents/networks.

	ENHANCEMENTS:

		* Change the queuing mechanism to a more dynamic one. At 
                  present the queue is a static array.
		* Make this program run as a detached process, TSR, or
  		  PM application with an improved user interface.
		* Provide for the support of multiple remote agents as described in
		  the LIMITATIONS section above.

	BUILD TOOLS:

		OS2

		This program was built using Novell's Lan Workplace for OS/2 (BSD 4.3
		sockets), MSC 5.10, MS link 5.01.21, POLYTRON Polymake V3.1.

		UNIX

		C compiler

	BUILD INSTRUCTIONS:

		required files are:  nba.c, nba.h, name.h, makefile(os2)

		unix> cc nba.c
		os2> make nba

	USAGE:

		nba [[-d] [[-a]{ipaddr}] [[-p]{port}] [[-w]{wport}]]
	  	where 	ipaddr = the Internet Address of the remote NBA Agent.
		         port   = the port used for name service transactions.
		                  Default is 137 (UDP Name Service Port)
		         wkport = the "well known port" used for NBA
		                  transactions. Default is 3000
		         -d     = Debug flag.  Debug mode prints messages to
					         STDERR.

		examples:

		>nba
		runs in silent server mode, port 137

		>nba -d
		runs in debug server mode, port 137

		>nba -d -a130.50.5.115 -p2000 -w5000
		runs in agent mode (for testing), port 2000, NBA port 5000,
		forwarding broadcasts to the remote agent at address 130.50.5.115.


*/

#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include "name.h"
#include "nba.h"
#ifdef OS2
#include <bsd43.h>
#endif

struct sockaddr_in sock = {AF_INET};
struct sockaddr_in bcast = {AF_INET};
struct sockaddr_in from = {AF_INET};
struct namepkt  nspkt;
struct ba_pkt   bapkt;
struct ba_header baheader;
struct ba_header baq[BAQSIZE];
struct hostent *host;
struct in_addr  inetaddr;
struct in_addr  inet_makeaddr();
ULONG           host_addr = 0L;
ULONG           bcast_addr = 0L;
ULONG           agent_addr = 0L;
ULONG           ipaddr;
ULONG           ipnet;
USHORT          baqindex = 0;
int             nspkt_size, bapkt_size;
USHORT          port = NAME_SERVICE_UDP_PORT;	/* the ns listen port */
USHORT          wkport = NBA_WK_PORT;	/* the ba listen port */
ULONG           batidx = 0;
int             len = sizeof(from);
int             debug = 0;
int             sig();
int             fd, fda;
char            myname[16];
char            othername[16];
BOOL            use_host_file = FALSE;
fd_set          sockset;

main(argc, argv)
	int             argc;
	char          **argv;
{
	char           *s;
	int             nfound;
	int             setres, optval;

	signal(SIGINT /* SIGHUP */ , sig);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
	while (--argc > 0 && (*++argv)[0] == '-') {
		s = argv[0] + 1;
		switch (*s) {
		case 'd':
			debug = 1;
			fprintf(stderr, "debug enabled\n");
			break;
		case 'p':
			port = atoi(++s);
			break;
		case 'w':
			wkport = atoi(++s);
			break;
		case 'a':
#ifdef	OS2
			ipnet = inet_addr(++s);
			ipaddr = inet_network(s);
			ipaddr = htons((short) ipaddr);
			agent_addr = (ipaddr << 16) | ipnet;
			/* inetaddr = inet_makeaddr(ipnet,ipaddr);  */
			/* agent_addr = inetaddr.S_un.S_addr;		  */
#else
			agent_addr = inet_addr(++s);
#endif
			break;
		default:
			fprintf(stderr, "usage: %s nba [[-d] [[-a]{ipaddr}] [[-p]{port}] [[-w]{wport}]]\n", argv[0]);
			exit(1);
		}
	}

	if (!agent_addr)
		use_host_file = TRUE;

	/* get local network information */
	if (gethostname(myname, sizeof(myname) - 1)) {
		perror("nba: gethostname()");
		exit(1);
	}
	if (debug)
		fprintf(stderr, "nba: myname = %s\n", myname);
	if (strlen(myname) > 15) {
		fprintf(stderr, "nba: - name too long\n");
		exit(1);
	}
	host = gethostbyname(myname);
	if (host) {
		bcopy(host->h_addr, (char *) &host_addr, host->h_length);
	} else {
		perror("nba: gethostbyname() \n");
		exit(1);
	}

	if (debug)
		fprintf(stderr, "host_addr  :0x%lx\n", ntohl(host_addr));
	if (debug && (agent_addr))
		fprintf(stderr, "agent_addr :0x%lx\n", ntohl(agent_addr));

	/* get broadcast IP Address */
	host = gethostbyname("broadcast");
	if (host) {
		bcopy(host->h_addr, (char *) &bcast_addr, host->h_length);
	} else {
		perror("nba: gethostbyname() \n");
		exit(1);
	}

	cvt(myname);		/* convert to upper case */

	/* get and bind a socket for netbios name service */
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("nba: socket()");
		exit(1);
	}
	sock.sin_port = htons(port);
	sock.sin_addr.S_un.S_addr = 0l;
	if (bind(fd, &sock, sizeof(sock)) < 0) {
		perror("nba: bind()");
		exit(1);
	}
	/* get and bind a socket for agent receive */
	if ((fda = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("nba: socket()");
		exit(1);
	}
	sock.sin_port = htons(wkport);
	sock.sin_addr.S_un.S_addr = host_addr;
	if (bind(fda, &sock, sizeof(sock)) < 0) {
		perror("nba: bind()");
		exit(1);
	}
	/* process all Broadcast Repeater (BA) and Name Service (NS) packets */
	while (1) {
		FD_ZERO(&sockset);
		FD_SET(fd, &sockset);
		FD_SET(fda, &sockset);
		/* wait for a pkt on one of the two sockets */
		if ((nfound = select(32, &sockset, NULL, NULL, NULL)) < 0) {
			perror("nba: select()");
			exit(1);
		}
		/* test for NS socket has data */
		if (FD_ISSET(fd, &sockset)) {
			process_ns();	/* process NS packets */
		}
		/* test for BA socket has data */
		if (FD_ISSET(fda, &sockset)) {
			process_ba();	/* process BA packets */
		}
	}
}				/* ba */


/*
 * process_ba() - process incoming BA agent packets
 */

process_ba()
{
	int             i, chsent;


	/* read the socket */
	if ((bapkt_size = recvfrom(fda, &bapkt,
			      sizeof(struct ba_pkt), 0, &from, &len)) < 0) {
		perror("nba: recvfrom()");
		exit(1);
	}
	if (debug) {
		fprintf(stderr, "|-- NBA PKT -------------------------------\n");
		fprintf(stderr, "| size   = 0x%x\n", bapkt_size);
		fprintf(stderr, "| port   = 0x%x\n", ntohs(from.sin_port));
		fprintf(stderr, "| addr   = 0x%lx\n", ntohl(from.sin_addr.S_un.S_addr));
		fprintf(stderr, "|----------------------------------------\n");
	}
	/* set up the agent tid and change the pkt tid */
	bapkt.baheader.ba_tid = htonl(++batidx);
	bapkt.namepkt.header.nm_tid = NLtoNS(bapkt.baheader.ba_tid);

	/* enqueue the header */
	while (baenq(&bapkt)) {
	};			/* keep trying until success (a header
				 * expires) */

	/* forward (broadcast) the packet to local net */
	sock.sin_port = htons(port);
	sock.sin_addr.S_un.S_addr = bcast_addr;

	if ((chsent = sendto(fd, &bapkt.namepkt, (int) (bapkt_size - BAHEADERSIZE), 0,
			     &sock, SOCKADDRSIZE)) < 0) {
		perror("nba: sendto()");
		exit(1);
	}
	if (debug)
		fprintf(stderr, ">>> Broadcast 0x%x bytes to	Port:0x%x  Addr:0x%lx\n",
			chsent, ntohs(sock.sin_port), ntohl(sock.sin_addr.S_un.S_addr));


}				/* process_ba */


/*
 * process_ns() - process incoming name service packets
 */

process_ns()
{
	int             i, chsent;
	struct ba_header *phdr;


	/* read the socket */
	if ((nspkt_size = recvfrom(fd, &bapkt.namepkt,
			     sizeof(struct namepkt), 0, &from, &len)) < 0) {
		perror("nba: recvfrom()");
		exit(1);
	}
	/* if broadcast encapsulate the NS packet and send to BA agent */
	if (!(ntohs(bapkt.namepkt.header.status) & NS_RES_MASK)) {
		/* skip the broadcast if it came from this node */
		if (from.sin_addr.S_un.S_addr != host_addr) {

			if (debug) {
				fprintf(stderr, "|-- NETBIOS PKT --------------------------\n");
				fprintf(stderr, "| size = 0x%x\n", nspkt_size);
				fprintf(stderr, "| port = 0x%x\n", ntohs(from.sin_port));
				fprintf(stderr, "| addr = 0x%lx\n", ntohl(from.sin_addr.S_un.S_addr));
				fprintf(stderr, "| tid  = 0x%x\n", ntohs(bapkt.namepkt.header.nm_tid));
				fprintf(stderr, "| type = 0x%x\n", ntohs(bapkt.namepkt.header.status));
				fprintf(stderr, "|--------------------------------------\n");
			}
			/*
			 * if we are running in server mode process the pkt
			 * locally
			 */
			if (use_host_file) {
				respond_local(&bapkt.namepkt);
				return;
			}
			/* set up the baheader */
			baheader.client_addr = from.sin_addr.S_un.S_addr;
			baheader.client_port = NStoNL(from.sin_port);
			baheader.host_addr = host_addr;
			baheader.ns_tid = NStoNL(bapkt.namepkt.header.nm_tid);

			/*
			 * prepend the packet (in bapkt.namepkt) with the
			 * baheader
			 */
			bcopy((char *) &baheader, (char *) &bapkt, BAHEADERSIZE);

			/* send the packet to the other agent */
			sock.sin_port = htons(wkport);	/* BA "well known" port */
			sock.sin_addr.S_un.S_addr = agent_addr;	/* BA agent address     */


			if ((chsent = sendto(fd, &bapkt, (int) (nspkt_size + BAHEADERSIZE), 0,
					     &sock, SOCKADDRSIZE)) < 0) {
				perror("nba: sendto()");
				exit(1);
			}
			if (debug)
				fprintf(stderr, ">>> Sent 0x%x bytes to	Port:0x%x  Addr:0x%lx\n",
					chsent, ntohs(sock.sin_port), ntohl(sock.sin_addr.S_un.S_addr));
		}
	}
	/* not a broadcast. Lookup in the queue, set up reply pkt if found */
	else {
		if (debug) {
			fprintf(stderr, "|-- NETBIOS PKT --------------------------\n");
			fprintf(stderr, "| size = 0x%x\n", nspkt_size);
			fprintf(stderr, "| port = 0x%x\n", ntohs(from.sin_port));
			fprintf(stderr, "| addr = 0x%lx\n", ntohl(from.sin_addr.S_un.S_addr));
			fprintf(stderr, "| tid  = 0x%x\n", ntohs(bapkt.namepkt.header.nm_tid));
			fprintf(stderr, "| type = 0x%x\n", ntohs(bapkt.namepkt.header.status));
			fprintf(stderr, "|--------------------------------------\n");
		}
		/* dequeue based on the nm_tid */
		if (!(badeq(NStoNL(bapkt.namepkt.header.nm_tid), &bapkt))) {

			/* restore the pkt tid */
			bapkt.namepkt.header.nm_tid = NLtoNS(bapkt.baheader.ns_tid);

			/* send the packet to the remote client */
			sock.sin_port = NLtoNS(bapkt.baheader.client_port);
			sock.sin_addr.S_un.S_addr = bapkt.baheader.client_addr;

			if ((chsent = sendto(fd, &bapkt.namepkt, nspkt_size, 0,
					     &sock, SOCKADDRSIZE)) < 0) {
				perror("nba: sendto()");
				exit(1);
			}
			if (debug)
				fprintf(stderr, ">>> Sent 0x%x bytes to	Port:0x%x  Addr:0x%lx\n",
					chsent, ntohs(sock.sin_port), ntohl(sock.sin_addr.S_un.S_addr));
		}
	}
}				/* process_ns */


/*
 * baenq - enqueue a BA header. returns: 0 if success At present the queue is
 * just an array of headers.
 */
int 
baenq(header)
	struct ba_header *header;
{
	int             i;
	ULONG           t;

	/* place the header at an empty (expired) location */
	for (i = 0; i < BAQSIZE; i++) {
		time(&t);
		if ((t - baq[i].time) > BAPKTLIFE) {
			bcopy((char *) header, (char *) &baq[i], BAHEADERSIZE);
			baq[i].time = t;	/* time stamp the header */
			return (0);
		}
	}

	if (debug)
		fprintf(stderr, "XXX Queue full.\n");

	return (1);
}

/*
 * badeq - dequeue a baheader based on a BATID returns: 0 if success At
 * present the queue is just an array of headers.
 */
int 
badeq(tid, header)
	ULONG           tid;
	struct ba_header *header;
{
	int             i;
	ULONG           t;

	/* search for header ba_tid matching the tid */
	for (i = 0; i < BAQSIZE; i++) {
		time(&t);
		/* skip the dead ones */
		if ((t - baq[i].time) < BAPKTLIFE) {
			if (baq[i].ba_tid == tid) {
				bcopy((char *) header, (char *) &baq[i], BAHEADERSIZE);
				return (0);
			}
		}
	}

	if (debug)
		fprintf(stderr, "XXX Header not found.\n");

	return (1);
}


/*
 * cvt - convert MYNAME to upper case
 */

cvt(src)
	char           *src;
{
	int             i;

	for (i = 0; i < strlen(src); i++) {
		if (isalpha(src[i]))
			src[i] = toupper(src[i]);
	}

	/* fill with blanks */

	for (; i <= 15; i++)
		src[i] = ' ';
}

/*
 * sig - signal handling
 */

sig()
{
#ifdef OS2
	soclose(fd);
	soclose(fda);
#endif
	exit(1);
}


/*
 * dns2nb - convert DNS name to NETBIOS name
 */

dns2nb(dnsp, nbp)
	char           *dnsp;	/* ptr to a DNS name */
	char           *nbp;	/* ptr to a 16 byte buffer */

{
	unsigned char   idx;
	unsigned char   left;
	unsigned char   right;

	/*
	 * a compressed Netbios name is always 32 bytes long, so we can loop
	 * for a fixed amount, as long as the initial length byte is skipped
	 */

	for (dnsp++, idx = 0; (idx < SZ_NCBNAME); idx++, nbp++) {
		left = (*dnsp++ - 'A') << 4;
		right = (*dnsp++ - 'A');
		*nbp = left + right;
	}
}				/* end dns2nb() */


/*
 * nb2dns - convert NETBIOS name to DNS (first level encoded) name
 */

nb2dns(nbp, dnsp)
	char           *dnsp;	/* ptr to a 32 byte DNS name */
	char           *nbp;	/* ptr to a 16 byte buffer */

{
	unsigned char   idx;
	unsigned char   left;
	unsigned char   right;

	for (idx = 0; (idx < SZ_NCBNAME); idx++, nbp++, dnsp++) {
		*dnsp = (*nbp >> 4) + 'A';
		*(++dnsp) = (*nbp & 0x0f) + 'A';
	}
}				/* end dns2nb() */


/*
 * respond_local - look up name in the hosts file and respond to the query if
 * found.
 */

respond_local(nspkt)
	struct namepkt *nspkt;
{

	char            nbname[16];
	char            temp[17];
	char           *chp;
	struct rr_trailer *trailer;
	struct rr_info *info;
	int             count;


	dns2nb(nspkt->records, nbname);

	/* strip the trailing spaces (null terminate it) */
	for (chp = nbname; isalpha(*chp); chp++);
	*chp = 0;

	if (debug)
		fprintf(stderr, "Hosts file look-up of \"%s\" \n", nbname);

	/* get the address from the hosts file */
	host = gethostbyname(nbname);

	if (host) {
		if (debug)
			fprintf(stderr, "Address found : 0x%lx\n",
				ntohl(*(long *) host->h_addr));

		trailer = (struct rr_trailer *) ((char *) nspkt + nspkt_size - 4);
		nspkt->header.status = htons(NM_QRY_RES);
		nspkt->header.qdcount = 0;
		nspkt->header.ancount = htons(1);
		trailer->ttl = htons(1);
		trailer->length = htons(6);
		info = (struct rr_info *) trailer;
		info->flags = 0;
		info->nbaddr = ntohl(*(long *) host->h_addr);

		/* send the response packet (back) to the client */
		if ((count = sendto(fd, nspkt,
				    nspkt_size + sizeof(struct rr_info) - 4,
				  0, &from, sizeof(struct sockaddr))) < 0) {
			perror("nsd: sendto()");
			exit(1);
		}
		if (debug)
			fprintf(stderr, ">>> Sent 0x%x bytes to	Port:0x%x  Addr:0x%lx\n",
				count, ntohs(from.sin_port), ntohl(from.sin_addr.S_un.S_addr));

	} else {		/* gethostbyname() failed */
		if (debug)
			fprintf(stderr, "Address not found.\n");
	}
}
