
/****************************************************************************
 ****************************************************************************

$Abstract: 
   Request Control  Block  structure  definition  used  to  convey BSD 4.3
   socket  request/reply  between drivers  and  library/user.
$
   The RCB can be  logically defined  as two different  sub structures the 
   Non IO operation RCB and the IO operation RCB. 

   DOS Host Resident Internet Protocols Request Control Block (RCB) Format
             (For Non-IO Operations)

            +=======================+===================+
            | 0    |                |                   |
            | 1    | RCB_next       | Used for link mgt.|
            | 2    |                |                   |
            | 3    |                |                   |
            |-----------------------|-------------------|
            | 4    |                |                   |
            | 5    | RCB_prev       | Used for link mgt.|
            | 6    |                |                   |
            | 7    |                |                   |
            |-----------------------|-------------------|
            | 8    |                |                   |
            | 9    | RCB_ESR        | Post address      |
            |10    |                |                   |
            |11    |                |                   |
            |-----------------------|-------------------|
            |12    |                |                   |
            |13    |                |                   |
            |14    |                |                   |
            |15    | RCB_reserved   |  For internal use |
            |16    |                |                   |
            |17    |                |                   |
            |18    |                |                   |
            |19    |                |                   |
            |-----------------------|-------------------|
            |20    | RCB_type       | BSD 4.3..         |
            |-----------------------|-------------------|
            |21    | RCB_command    | Command code      |
            |-----------------------|-------------------|
            |22    | RCB_socket     | Socket ID         |
            |-----------------------|-------------------|
            |23    | RCB_status     | Status & Ret code |
            |-----------------------|-------------------|
            |24    | RCB_param      | Length determined | Refer to particular 
            |      | (Variable)     | by RCB_command    | command.  
            +-----------------------+-------------------+
             xx 


   DOS Host Resident Internet Protocols Request Control Block (RCB) Format
   
            (For Data-IO Operations)

            +=======================+===================+
            | 0    |                |                   |
            | 1    | RCB_next       | Used for link mgt.|
            | 2    |                |                   |
            | 3    |                |                   |
            |-----------------------|-------------------|
            | 4    |                |                   |
            | 5    | RCB_prev       | Used for link mgt.|
            | 6    |                |                   |
            | 7    |                |                   |
            |-----------------------|-------------------|
            | 8    |                |                   |
            | 9    | RCB_ESR        | Post address      |
            |10    |                |                   |
            |11    |                |                   |
            |-----------------------|-------------------|
            |12    |                |                   |
            |13    |                |                   |
            |14    |                |                   |
            |15    | RCB_reserved   |  For internal use |
            |16    |                |                   |
            |17    |                |                   |
            |18    |                |                   |
            |19    |                |                   |
            |-----------------------|-------------------|
            |20    | RCB_type       | BSD 4.3..         |
            |-----------------------|-------------------|
            |21    | RCB_command    | Command code      |
            |-----------------------|-------------------|
            |22    | RCB_socket     | Socket ID         |
            |-----------------------|-------------------|
            |23    | RCB_status     | Status & Ret code |
            |-----------------------|-------------------|
            |24    | RCB_flags      | Flag Indicators   | 
            |25    |                | MSG_OOB/MSG_PEEK  |
            |-----------------------|-------------------|
            |26    | RCB_port       | Port ID. Ignored  |
            |27    |                | for SEND/RECV     |
            |-----------------------|-------------------|
            |28    |                |                   |
            |29    | RCB_ip_addr    | IP Addr. Ignored  |  
            |30    |                | for SEND/RECV     |
            |31    |                |                   |
            |-----------------------|-------------------|
            |32    | totallen       | Total length of   |
            |33    |                | all fragments.    |
            |-----------------------|-------------------|
            |34    | RCB_frag_cnt   | Fragment Count    |
            |35    |                |                   |
            |-----------------------|-------------------|
            |36    | RCB_frag [0]   | Fragment 0        |
            |-----------------------|-------------------|
            |42    | RCB_frag [1]   | Fragment 1        |
            |-----------------------|-------------------|
            |48    | RCB_frag [2]   | Fragment 2        |
            |-----------------------|-------------------|
            |54    | RCB_frag [3]   | Fragment 3        |
            |-----------------------|-------------------|
            |60    | RCB_frag [4]   | Fragment 4        |
            |-----------------------|-------------------|
            |66    | RCB_frag [5]   | Fragment 5        |
            |-----------------------|-------------------|
            |72    | RCB_frag [6]   | Fragment 6        |
            |-----------------------|-------------------|
            |78    | RCB_frag [7]   | Fragment 7        |
            +=======================+===================+
             84
 ****************************************************************************
 ****************************************************************************/

#ifndef  _RCB

#define _RCB

#define MAXSG    	8 		/* Max number of scatter/gather */
#define MAXTOTALLEN 65535   /* Max Total length of data per io */

typedef    unsigned char    u8bit;
typedef    unsigned short   u16bit;
typedef    unsigned long    u32bit;

  /* RCB defines the static part of both Non IO and IO RCBs    */

typedef    struct RCB_static {
    u32bit         RCB_next;           /* RCB management       */
    u32bit         RCB_prev;           /* RCB management       */
    u32bit         RCB_ESR;            /* post address         */
    u8bit          RCB_reserved [8];   /* workspace            */
    u8bit          RCB_type;           /* for RCB de-muxing    */
    u8bit          RCB_command;        /* command code         */
    u8bit          RCB_socket;         /* socket               */
    u8bit          RCB_status;         /* status & return code */
};

  /* frag describes the fragments                              */

struct    frag {  
    u32bit    fragptr;             /* pointer to the data      */
    u16bit    fraglen;             /* length                   */
};

  /* RCB_io defines the scatter gather arrray for IO RCBs      */
typedef    struct    RCB_io {
    u16bit          totallen;
    u16bit          RCB_fragcnt;   /* number of fragments      */
    struct  frag    RCB_frag [8];  /* the fragments. Max = 8   */
};

/***************************************************************/

/* values for RCB_type */

#define    RCB_BSD43    1            /* BSD 4.3 Internet       */


/* Values for RCB_command */
/* Non-IO Operations      */

#define    ACCEPT          1
#define    BIND            2
#define    CLOSE           3
#define    CONNECT         4
#define    GETMYIPADDR     5
#define    GETMYMACADDR    6
#define    GETPEERNAME     7
#define    GETSOCKNAME     8 
#define    GETSOCKOPT      9 
#define    GETSUBNETMASK   10
#define    IOCTL           11
#define    LISTEN          12
#define    SELECT          13
#define    SETMYIPADDR     14
#define    SETSOCKOPT      15
#define    SHUTDOWN        16
#define    SOCKET          17

/* Data-IO Operations     */

#define    RECV            18
#define    RECVFROM        19
#define    SEND            20
#define    SENDTO          21

/***************************************************************/


/* Sockaddr structure has the IPADDR and the PORT              */

struct    RCB_sockaddr {
    u16bit    port;                  /* UDP/TCP port           */
    u32bit    ip_addr;               /* IP address             */
};


/* Define various rcb structures for the socket commands.      */

/***************************************************************/
/**           RCB structures for NON IO operations            **/
/***************************************************************/

typedef struct  rcb_accept {
    struct    RCB_static      rcb;
    struct    RCB_sockaddr    addr;
} rcb_accept;

typedef struct  rcb_bind {
    struct    RCB_static      rcb;
    struct    RCB_sockaddr    addr;
} rcb_bind;
 
typedef struct  rcb_close {
    struct    RCB_static      rcb;
} rcb_close;

typedef struct  rcb_connect {
    struct    RCB_static      rcb;
    struct    RCB_sockaddr    addr;
} rcb_connect;

typedef struct  rcb_getmyipaddr {
    struct    RCB_static      rcb;
    struct    RCB_sockaddr    addr;
} rcb_getmyipaddr;

typedef struct  rcb_getmymacaddr {
    struct    RCB_static      rcb;
    u8bit                     rcb_macaddr[6];
} rcb_getmymacaddr;

typedef struct  rcb_getpeername {
    struct    RCB_static      rcb;
    struct    RCB_sockaddr    addr;
} rcb_getpeername;

typedef struct  rcb_getsockname {
    struct    RCB_static      rcb;
    struct    RCB_sockaddr    addr;
} rcb_getsockname;

typedef struct  rcb_getsockopt {
    struct    RCB_static      rcb;
    u16bit                    optname;
    u16bit                    optval; 
    u16bit                    linger;
} rcb_getsockopt;

typedef struct  rcb_ioctl {
    struct    RCB_static      rcb;
    u32bit                    arg;
    u16bit                    ioctl;
} rcb_ioctl;

typedef struct  rcb_listen {
    struct    RCB_static      rcb;
    u16bit                    backlog;        
} rcb_listen;

typedef struct  rcb_select {
    struct    RCB_static      rcb;
    u16bit                    socket_count;
    fd_set                    readfds;
    fd_set                    writefds;
    fd_set                    exceptfds;
    unsigned  long            ticks;
} rcb_select;

typedef struct  rcb_setsockopt {
    struct    RCB_static      rcb;
    u16bit                    optname;
    u16bit                    optval; 
    u16bit                    linger;
} rcb_setsockopt;

typedef struct  rcb_shutdown {
    struct    RCB_static      rcb;
    u16bit                    how;
} rcb_shutdown;

typedef struct  rcb_socket {
    struct    RCB_static      rcb;
    u16bit                    protocol;
} rcb_socket;


/***************************************************************/
/**            RCB structures for IO operations               **/
/***************************************************************/

typedef struct  rcb_recv {
    struct    RCB_static      rcb;
    u16bit                    flags;
    struct    RCB_sockaddr    from;
    struct    RCB_io          recv_io;
} rcb_recv;

typedef struct  rcb_recvfrom {
    struct    RCB_static      rcb;
    u16bit                    flags;
    struct    RCB_sockaddr    from;
    struct    RCB_io          recvfrom_io;
} rcb_recvfrom;

typedef struct  rcb_send {
    struct    RCB_static      rcb;
    u16bit                    flags;
    struct    RCB_sockaddr    to;
    struct    RCB_io          send_io;
} rcb_send;

typedef struct  rcb_sendto {
    struct    RCB_static      rcb;
    u16bit                    flags;
    struct    RCB_sockaddr    to;
    struct    RCB_io          sendto_io;
} rcb_sendto;

#endif

