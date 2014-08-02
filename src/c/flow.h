/* 
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
 *
 *  flow.h
 *  picflow
 *
 *  Created by Thomas Zink on 3/2/10.
 *
 */

#ifndef _FLOW_H_
#define _FLOW_H_

#include <netinet/in.h> // in_addr
#include <pcap.h>		// timeval
#include "protocols.h"	// protocol types
#ifdef __cplusplus
#include <iostream>
using namespace std;
#endif

enum picdfi_type {
	type_unidentified = 0x00,
	type_possible = 0x01,
	type_p2p = 0x02,
	type_nonp2p = 0x04
};

enum identification_type {
	payload_match,
	port_match,
	tcp_certain,
	tcp_none,
	udp_certain,
	udp_uncertain,
	no_match
};

enum verification_type {
	na_positive,			// could not verify, identified p2p
	na_negative,			// could not verify, identified nonp2p
	true_positive,			// identified and verified p2p
	false_positive,			// identified p2p, verified nonp2p
	true_negative,			// identified and verified nonp2p
	false_negative			// identified nonp2p, verified p2p
};

/*
 pic_service
 a service on one side identified by {addr, port}.
*/
typedef struct pic_service_s {
	struct in_addr addr;
	u_short port;
#ifdef __cplusplus
	// con/de-structor
	pic_service_s ();
	pic_service_s (struct in_addr addr, u_int16_t port);
	~pic_service_s ();
	// i/o
	friend ostream & operator<< (ostream & stream,const pic_service_s & o);
	bool operator< (const pic_service_s & o) const;
	bool operator== (const pic_service_s & o) const;
#endif
} pic_service_t;

/*
 pic_connection
 a connection is composed of two connected services
 and a protocol, that is the pair {sa,sp,da,dp,proto}
 (a: address, p: port). it can be used as an identifier
 for a flow, ie flow_id.
*/
typedef struct pic_connection_s {
	struct pic_service_s * lower;
	struct pic_service_s * upper;
	u_char ip_p;
#ifdef __cplusplus
	// constructor / destructor
	pic_connection_s ();
	pic_connection_s (const u_char * ippacket);
	~pic_connection_s ();
	
	// operators
	friend ostream & operator<< (ostream & stream, const pic_connection_s & o);
	bool operator< (const pic_connection_s & o) const;
	bool operator== (const pic_connection_s & o) const;
#endif
} pic_connection_t;

/*
 pic_flow
 information kept for a flow, like created, touched,
 number of packets / bytes, the flow type and so on
*/
typedef struct pic_flow_s {
	struct timeval created;
	struct timeval touched;
	u_int32_t npackets;
	u_int32_t nbytes;
	u_char options;
	picdfi_type flow_type;
	identification_type id_type;
#ifdef __cplusplus
	// constructor / destructor
	pic_flow_s ();
	pic_flow_s (const struct pcap_pkthdr * header);
	~pic_flow_s ();
	// operators
	friend ostream & operator<< (ostream & stream, const pic_flow_s & o);
	bool operator== (const pic_flow_s & o);
	// others
	int update (const struct pcap_pkthdr * header);
#endif
} pic_flow_t;


/*
 pic_ident
 values referring to an identification table entry.
 we need the last touched timestamp and a certain flag
*/
typedef struct pic_ident_s {
	struct timeval touched;
#ifndef __cplusplus
	u_char certain;
#endif
#ifdef __cplusplus
	bool certain;
	pic_ident_s ();
	pic_ident_s (struct timeval ts, bool certain);
	~pic_ident_s ();
	int update (struct timeval ts, bool certain);
	friend ostream & operator<< (ostream & stream, const pic_ident_s & o);
#endif
} pic_ident_t;

/*
 pic_stat
 statistics for flows and verification
*/
typedef	struct pic_stat_s {
	u_int32_t nflows;
	u_int32_t npackets;
	u_int32_t nbytes;
#ifdef __cplusplus
	pic_stat_s ();
	pic_stat_s (pic_flow_s f);
	~pic_stat_s ();
	int update (pic_flow_s f);
	friend ostream & operator<< (ostream & stream, const pic_stat_s & o);
#endif
} pic_stat_t;

// a flow handler type definition
typedef void (*flow_handler_f) (pic_connection_t conn, pic_flow_t flow);

#endif // _FLOW_H_
