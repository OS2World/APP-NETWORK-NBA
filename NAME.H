/*
----------------------------------------------------------------------------

        Copyright (C) 1990 Novell, Inc.
	
        This software may be freely copied and distributed, provided the 
        above copyright notice is included. It may not be sold, in whole
        or in part, without the prior written consent of Novell, Inc.

----------------------------------------------------------------------------
*/

#define	IP_DGRAM_SZ	576
#define	IP_HDR_SZ	20
#define	UDP_HDR_SZ	8
#define SZ_BUFFER	(IP_DGRAM_SZ - IP_HDR_SZ - UDP_HDR_SZ)
#define	SZ_MAXPKTDATA	576	/* maximum data in a packet */

/****************************************************************************
 * Domain Name Packet Definitions
 ***************************************************************************/


#define	NM_REG_REQ	0x2910
#define	NM_RES		0xad80
#define	NM_QRY		0x0110
#define	NM_QRY_RES	0x8500
#define NM_QRY_RES1	0x8580
#define	NODE_STATUS_REQ	0x0010
#define	NODE_STATUS_RES 0x8400
#define	NM_OVR_REQ	0x2810
#define	NM_RLS_REQ	0x3010
#define PKT_MSK		0xfdf0	/* Mask of bits used for packet type. */
#define RCODE_MSK	0x000f	/* Mask of bits used for rcode */

/*
 * Mask values for NM_FLAGS. These values treat the fields,
 * OPCODE, NM_FLAGS, and RCODE as one word (16 bits).
 */

#define	NS_BROADCAST	0x0001
#define	NS_RESRVD1	0x0002
#define	NS_RESRVD2	0x0004
#define	NS_RA		0x0008
#define	NS_RD		0x1000
#define	NS_TC		0x2000	/* truncation bit */
#define	NS_AA		0x4000

/* error codes for RCODE field in packet header */

#define	FMT_ERR	0x1	/* Invalidly Formatted Request */
#define	SRV_ERR	0x2	/* Server Failure */
#define	IMP_ERR	0x4	/* Unsupported Request */
#define	RFS_ERR	0x5	/* Registration Refusal */
#define	ACT_ERR	0x6	/* Active erroe, name is owned by another node. */
#define	CFT_ERR	0x7	/* Name is in conflict */

/* type values */

#define	NS_A		0x0100	/* IP address RR */
#define	NS_NS		0x0002	/* Name Server RR */
#define	NS_NB		0x0020	/* General Name Service RR */
#define	NS_NBSTAT	0x0021	/* Node Status RR */
#define	NS_NULL		0x000a	/* NULL RR - see WACK definition */
#define NS_IN		0x0001  /* Internet class */

/* values for NB_FLAG field in RR data */

#define NS_GROUP	0x8000	/* Group Bit, 1 == Group Netbios Name */
#define NS_MNODE	0x4000
#define NS_PNODE	0x2000
#define NS_DRG		0x1000
#define NS_BNODE	0x0000
#define NS_CNF		0x0800
#define NS_ACT		0x0400
#define NS_PRM		0x0200

/* masks for NB_FLAG field in name data entry */

#define NS_GROUPMSK	~0x8000	/* Group Name Flag */
#define NS_ONTMSK	~0x6000	/* Owner Node Type */
#define NS_STATEMSK	~0x1d00	/* Name State Bits */


/****************************************************************************
 * Question Section trailer: preceded by a compressed Netbios name
 ***************************************************************************/

struct quest_trailer {
    unsigned short type;
    unsigned short class;
}; /* 4 bytes long */

/****************************************************************************
 * Resource Record trailer: preceded by a compressed Netbios name, followed
 * by a variable data section
 ***************************************************************************/

struct rr_trailer {
    unsigned short  type;
    unsigned short  class;
    unsigned long ttl;
    unsigned short  length;
}; /* 10 bytes long */

struct rr_info {
    struct rr_trailer	trailer;
    unsigned short       flags;
    long 		 nbaddr;
}; /* 16 bytes long */

struct nmpkt_hdr {
    unsigned short nm_tid;	/* transaction id */
    unsigned short status;	/* opcode, flags, return code */
    unsigned short qdcount;	/* number of question entries */
    unsigned short ancount;	/* number of answer records */
    unsigned short nscount;	/* number of authority records */
    unsigned short arcount;	/* number of additional records */
}; /* 12 bytes long */

struct namepkt {
    struct nmpkt_hdr header;	
    unsigned char records[SZ_BUFFER - sizeof(struct nmpkt_hdr)];
};

#define	NAME_SERVICE_UDP_PORT	137
