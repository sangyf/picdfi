/*
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
 *
 *  handler.cpp
 *  picflow
 *
 *  Created by Thomas Zink on 3/12/10.
 *
 */
#ifdef __unix__
#include <netinet/ether.h>
#endif
#include "handler.h"
#include "protocols.h"
#include "flow.h"
#include "optpar.h"
#include "tables.h"
#include <map>
#include "defines.h"
#include <assert.h>

/*
 external vars
 */
extern optarg_t* optargs;
/*
 tables and statistics defined in tables.cpp
 */
extern flow_table_t flows;
extern identification_table_t services;
extern statistic_table_t statistics;
extern verification_table_t verify;
extern vstat_table_t vstats;
extern u_int32_t ip_packets_scanned;
extern u_int32_t ip_bytes_scanned;
extern long last_aged;
extern flow_handler_f flow_callback;

void
ethernet_handler (u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
	static u_int32_t numpacket = 0;
	static bool warning_used = false;
	
	// get ethernet header
	ether_t * eth = (ether_t *) (packet);
	u_short ether_type = ntohs(eth->ether_type);
	
	// print some output
	// sth fishy going on here, need printf between ntoa
	// else will only return previous value!
#if DEBUG >= 1
	printf("%i: %li,%li\n",numpacket,(long int)header->ts.tv_sec,(long int)header->ts.tv_usec);
	char * shost = ether_ntoa((struct ether_addr *)eth->ether_shost);
	printf("(ETH) %s > ", shost);
	char * dhost = ether_ntoa((struct ether_addr *)eth->ether_dhost);
	printf("%s ", dhost);
	printf("type: %x\n", ether_type);
#endif
	
	// check for ageing
	// ignore microsecs
	if ((header->ts.tv_sec - last_aged) > optargs->t_age) {
		do_ageing(header, flow_callback);
		last_aged = header->ts.tv_sec;
	}	
	
	// check network layer proto and proceed
	switch (ether_type) {
		case ETHERTYPE_IP:
			ip_handler(args, header, (packet + ETHER_HDR_LEN));
			break;
		default:
			if (warning_used == false) {
				fprintf(stderr,"WARNING: only IP supported\n\n\n\n");
				warning_used = true;
			}
			break;
	}
#if DEBUG >= 1
	printf("\n");
#endif
	numpacket++;
}

void
chdlc_handler (u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
	static u_int32_t numpacket = 0;
	static bool warning_used = false;
	chdlc_t * chdlc = (chdlc_t *) (packet);
#if DEBUG >= 1	
	printf("%i: %li,%li\n",numpacket,(long int)header->ts.tv_sec,(long int)header->ts.tv_usec);
	printf("(chdlc) %c, %c, %i\n", chdlc->address, chdlc->control, ntohs(chdlc->code));
#endif

	// check for ageing
	// ignore microsecs
	if ((header->ts.tv_sec - last_aged) > optargs->t_age) {
		do_ageing(header, flow_callback);
		last_aged = header->ts.tv_sec;
	}	
	
	switch (ntohs(chdlc->code)) {
		case CHDLC_TYPE_IP:
			ip_handler(args, header, (packet + CHDLC_HDRLEN));
			break;
		default:
			if (warning_used == false) {
				fprintf(stderr,"WARNING: only IP supported\n\n\n\n");
				warning_used = true;
			}
			break;
	}
	numpacket++;
}

void
ip_handler (u_char * args, const struct pcap_pkthdr *header, const u_char * ippacket)
{
	// assumes *packet points at the beginning of the IP packet!
	// only call for raw IP or after adjusting pointers in correct
	// frame_handler!
	static bool warning_used = false;
	// packet related
	ip_t * ip = (ip_t *) (ippacket);
	size_t size_ip = (ip->ip_hl*4);
	void * segment = NULL;
	size_t segment_hdr_size = 0;
	const u_char * payload;
	// return values from flow / service tables
	pair<map<pic_connection_t,pic_flow_t>::iterator,bool> ret_flows;
	u_char ret_services;
	
#if DEBUG >= 1
	char sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip->ip_src), sip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip->ip_dst), dip, INET_ADDRSTRLEN);
	printf("(IP) %s >> %s p: %d\n", sip, dip, ip->ip_p);
#endif	
	
	switch (ip->ip_p) {
		case IPPROTO_TCP:
			segment = (tcp_t *) (ippacket + size_ip);
			segment_hdr_size = ((tcp_t *)segment)->th_off * 4;
#if DEBUG >= 1
			tcp_handler(args, header, ippacket);
#endif
			break;
		case IPPROTO_UDP:
			segment = (udp_t *) (ippacket + size_ip);
			segment_hdr_size = 8;
#if DEBUG >= 1
			udp_handler(args, header, ippacket);
#endif
			break;
		default:
			if (warning_used == false) {
				fprintf(stderr,"WARNING: only TCP / UDP supported\n\n\n\n");
				warning_used = true;
			}
			return;
			break;
	}
		
	// ok, we got TCP or UDP
	payload = (ippacket + size_ip + segment_hdr_size);
	ret_flows = flow_table_update(args, header, ippacket);
	
	// check if we need identification
	if (ret_flows.first->second.flow_type <= type_possible) {
		ret_services = identify_flow(ret_flows.first,payload);
	}
#if DEBUG == 0
	// update and output progress
	cout << "\rip packets scanned: \x1b[33m" << ++ip_packets_scanned << "\x1b[0m" << endl;
	ip_bytes_scanned += header->len;
	cout << "\rip bytes scanned: \x1b[34m" << ++ip_bytes_scanned << "\x1b[0m" << endl;
	cout << "\ractive flows: \x1b[35m" << flows.size() << "       \x1b[0m" << endl;
	cout << "\ridentification entries: \x1b[35m" << services.size() << "       \x1b[0m\x1b[3A";	
#endif
}

void
tcp_handler (u_char * args, const struct pcap_pkthdr *header, const u_char * ippacket)
{
#if DEBUG >= 1
	ip_t * ip = (ip_t *) (ippacket);
	tcp_t * tcp = (tcp_t *) (ippacket + (ip->ip_hl*4));
	printf("(TCP) sport: %hu dport: %hu\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
#endif
}

void
udp_handler (u_char * args, const struct pcap_pkthdr *header, const u_char * ippacket)
{
#if DEBUG >= 1
	ip_t * ip = (ip_t *) (ippacket);
	udp_t * udp = (udp_t *) (ippacket + (ip->ip_hl*4));
	printf("(UDP) sport: %hu dport: %hu\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
#endif
}

void
verify_flow (pic_connection_t conn, pic_flow_t flow)
{
	verification_table_t::iterator it_v;
	it_v = verify.find(conn);
#if ASSERT == 1
	assert (it_v != verify.end());
#endif
#if DEBUG >= 2
	cout << "(verify) " << conn << endl;
	cout << "(verify) " << flow << endl;
	if (it_v == verify.end()) cout << "(verify) no entry\n";
	else cout << "(verify) " << it_v->second << endl;
#endif
	if (it_v == verify.end() || it_v->second.flow_type == type_unidentified) {
		// unable to verify
		switch (flow.flow_type) {
			case type_p2p:
#if DEBUG >= 2
				cout << "(verify) NP" << endl;
#endif
				vstats[na_positive].update(flow);
				break;
			case type_nonp2p:
			case type_possible:
			case type_unidentified:
#if DEBUG >= 2
				cout << "(verify) NN" << endl;
#endif			
				vstats[na_negative].update(flow);
				break;
			default:
				break;
		}
	} else {
#if DEBUG >= 2
		cout << "(verify) " << it_v->second << endl;
#endif
		switch (it_v->second.flow_type) {
			case type_p2p:
				switch (flow.flow_type) {
					case type_p2p:
#if DEBUG >= 2
						cout << "(verify) TP" << endl;
#endif						
						vstats[true_positive].update(flow);
						break;
					case type_nonp2p:
					case type_possible:
					case type_unidentified:
#if DEBUG >= 2
						cout << "(verify) FN" << endl;
#endif						
						vstats[false_negative].update(flow);
						break;
					default:
						break;
				}
				break;
			case type_nonp2p:
			case type_possible:
			case type_unidentified:
				switch (flow.flow_type) {
					case type_p2p:
#if DEBUG >= 2
						cout << "(verify) FP" << endl;
#endif						
						vstats[false_positive].update(flow);
						break;
					case type_nonp2p:
					case type_possible:
					case type_unidentified:
#if DEBUG >= 2
						cout << "(verify) TN" << endl;
#endif						
						vstats[true_negative].update(flow);
						break;
					default:
						break;
				}
				break;
			default:
				break;
		}
	}

}

void
update_stats_verify_flow (pic_connection_t conn, pic_flow_t flow)
{
	statistics[flow.flow_type].update(flow);
	verify_flow(conn, flow);
}

void
update_stats  (pic_connection_t conn, pic_flow_t flow)
{
	statistics[flow.flow_type].update(flow);
}

void
update_stats_print_flow (pic_connection_t conn, pic_flow_t flow)
{
	statistics[flow.flow_type].update(flow);
	cout << "\n\t" << conn << " : " << flow << endl;
}