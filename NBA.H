/*
----------------------------------------------------------------------------

        Copyright (C) 1990 Novell, Inc.
	
        This software may be freely copied and distributed, provided the 
        above copyright notice is included. It may not be sold, in whole
        or in part, without the prior written consent of Novell, Inc.

----------------------------------------------------------------------------

	 NBA.H   header file for nba.c

*/

/******* "ignore" this stuff ******/
#ifndef FD_SET
#define	NBBY	8		/* number of bits in a byte */
/*
 * Select uses bit masks of file descriptors in longs.
 * These macros manipulate such bit fields (the filesystem macros use chars).
 * FD_SETSIZE may be defined by the user, but the default here
 * should be >= NOFILE (param.h).
 */
#ifndef	FD_SETSIZE
#define	FD_SETSIZE	32
#endif

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */
#ifndef howmany
#define	howmany(x, y)	(((x)+((y)-1))/(y))
#endif

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif
/**************** real stuff below here *****************/



typedef  	unsigned short 		USHORT;
typedef  	unsigned long  		ULONG;
typedef  	unsigned 				BOOL;

#define		TRUE						1
#define		FALSE 					0

#define 		NBA_WK_PORT  			3000   		/* an unassigned port */
#define 		BAQSIZE					100 
#define 		BAPKTLIFE    			5           /* packet life */
#define		SZ_NCBNAME				16
#define 		SOCKADDRSIZE  			sizeof(struct sockaddr_in)
#define 		AGENT_NAME_LEN 		11 
#define 		FILE_NAME_LEN  		80 


/* BA status codes */
#define 		BA_SEND					0
#define 		BA_REPLY 				1
#define 		BA_ERROR					-1

#define 		NS_RES_MASK				0x8000	/* mask for the NS response bit */

/* conversion macros */
	/* convert network order long to network order short */
#define 		NLtoNS(x)				htons((USHORT)ntohl(x)) 
	/* convert network order short to network order long */
#define 		NStoNL(x)				htonl((ULONG)ntohs(x))

struct ba_header {
	ULONG   	status;				/* command codes for BA agents */
	ULONG	  	time;					/* time stamp for packet expiration */
	ULONG 	ns_tid;				/* name service transaction id */
	ULONG 	ba_tid;				/* BA agent transaction id */
	ULONG  	host_addr;			/* BA agent address */
	ULONG 	client_addr;		/* NS client address   */
	ULONG 	client_port;		/* NS client port */
#define 		BAHEADERSIZE			sizeof(struct ba_header)
};

struct ba_pkt {
	struct 	ba_header baheader;
	struct 	namepkt   namepkt;
#define 		BAPKTSIZE				sizeof(struct ba_header) + SZ_BUFFER
};


