/*
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
 *
 */
#ifndef _PROTOCOLS_H_
#define _PROTOCOLS_H_

#define __FAVOR_BSD // this is to make use of bsd style protocol structs

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// typedefs for convenience and consistency
typedef struct ether_header ether_t;
typedef struct ip ip_t;
typedef struct tcphdr tcp_t;
typedef struct udphdr udp_t;


/*
	CHDLC
*/
#define CHDLC_HDRLEN 		4
#define CHDLC_UNICAST		0x0f
#define CHDLC_BCAST			0x8f
#define CHDLC_TYPE_SLARP 	0x8035
#define CHDLC_TYPE_CDP		0x2000
#define CHDLC_TYPE_IP		0x0800

typedef struct chdlc_hdr_s {
	u_char	address;
	u_char	control;
	u_short code;
} chdlc_t;
/* CHDLC */



#endif