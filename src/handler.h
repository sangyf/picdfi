/*
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
 *
 *  handler.h
 *  picflow
 *
 *  Created by Thomas Zink on 3/12/10.
 *
 */
#ifndef _HANDLER_H_
#define _HANDLER_H_

#include <pcap.h>			// pcap packet capturing
#include "flow.h"

/* 
 handlers for the different layers
 we could do this all in one function actually
 and prevent function call overhead.
 however, this would decrease readability and maintainability
 greatly
 */
void ethernet_handler (u_char * args, const struct pcap_pkthdr *header, const u_char * packet);
void chdlc_handler (u_char * args, const struct pcap_pkthdr *header, const u_char * packet);
void ip_handler (u_char * args, const struct pcap_pkthdr *header, const u_char * ippacket);
void tcp_handler (u_char * args, const struct pcap_pkthdr *header, const u_char * ippacket);
void udp_handler (u_char * args, const struct pcap_pkthdr *header, const u_char * ippacket);
void verify_flow (pic_connection_t conn, pic_flow_t flow);
void update_stats (pic_connection_t conn, pic_flow_t flow);
void update_stats_verify_flow (pic_connection_t conn, pic_flow_t flow);
void update_stats_print_flow (pic_connection_t conn, pic_flow_t flow);

#endif // _HANDLER_H_
