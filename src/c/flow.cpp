/*
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
 *
 *  flow.c
 *  picflow
 *
 *  Created by Thomas Zink on 3/2/10.
 *
 */

#include "flow.h"
#include "defines.h"
#include <arpa/inet.h> // inet_ntop
#include <iomanip> // setw

#ifdef __cplusplus

/*
 pic_service_t
*/
pic_service_s::
pic_service_s () {}

pic_service_s::
pic_service_s (struct in_addr addr, u_short port)
{
	this->addr = addr;
	this->port = port;
}

pic_service_s::
~pic_service_s () {}

ostream & operator<< (ostream & stream, const pic_service_s & o)
{
	char addr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(o.addr), addr, INET_ADDRSTRLEN);
	stream << addr << "," << ntohs(o.port);
	return stream;
}

bool pic_service_s::
operator< (const pic_service_s & o) const
{
	return (
		this->addr.s_addr == o.addr.s_addr ? this->port < o.port : this->addr.s_addr < o.addr.s_addr
	);
}

bool pic_service_s::
operator== (const pic_service_s & o) const
{
	return (
		this->addr.s_addr == o.addr.s_addr &&
		this->port == o.port
	);
}

/*
 pic_connection_t
*/
pic_connection_s::
pic_connection_s () {}


pic_connection_s::
pic_connection_s (const u_char * ippacket)
{
	struct in_addr la, ua;
	u_int16_t lp, up;
	ip_t * ip = (ip_t *) ippacket;
	
	if (ip->ip_p == IPPROTO_TCP) {
		tcp_t * tcp = (tcp_t *)(ippacket + ip->ip_hl*4);
		if (ip->ip_src.s_addr <= ip->ip_dst.s_addr) {
			la = ip->ip_src;
			ua = ip->ip_dst;
			lp = tcp->th_sport;
			up = tcp->th_dport;
		} else {
			ua = ip->ip_src;
			la = ip->ip_dst;
			up = tcp->th_sport;
			lp = tcp->th_dport;
		}
	} else if (ip->ip_p == IPPROTO_UDP) {
		udp_t * udp = (udp_t *)(ippacket + sizeof(ip_t));
		if (ip->ip_src.s_addr <= ip->ip_dst.s_addr) {
			la = ip->ip_src;
			ua = ip->ip_dst;
			lp = udp->uh_sport;
			up = udp->uh_dport;
		} else {
			ua = ip->ip_src;
			la = ip->ip_dst;
			up = udp->uh_sport;
			lp = udp->uh_dport;
		}
	} else {
		return;
	}
	
	this->lower = new pic_service_t (la,lp);
	this->upper = new pic_service_t (ua,up);
	this->ip_p = ip->ip_p;
}

pic_connection_s::
~pic_connection_s ()
{
	// this leads to malloc errors, dky
	/*
	delete this->lower;
	delete this->upper;
	 */
}

ostream & operator<< (ostream & stream, const pic_connection_s & o)
{
	stream << *(o.lower) << "," << *(o.upper) << "," << int(o.ip_p);
	return stream;
}

bool pic_connection_s::
operator< (const pic_connection_s & o) const
{
	bool lt;
	lt = *(this->lower) < *(o.lower);
	if (!lt) {
		bool eq = *(this->lower) == *(o.lower);
		if (eq) {
			lt = *(this->upper) < *(o.upper);
			if (!lt) {
				eq = *(this->upper) == *(o.upper);
				if (eq) {
					lt = (this->ip_p < o.ip_p);
				}
			}
		}
	}
	return(lt);
}

bool pic_connection_s::
operator== (const pic_connection_s & o) const {
	return (
		*(this->lower) == *(o.lower) &&
		*(this->upper) == *(o.upper) &&
		this->ip_p == o.ip_p
	);
}

/*
 pic_flow_t
*/
pic_flow_s::
pic_flow_s ()
{
	this->npackets = 0;
	this->nbytes = 0;
	this->options = 0;
	this->flow_type = type_unidentified;
	this->id_type = no_match;
}

pic_flow_s::
pic_flow_s (const struct pcap_pkthdr *header)
{
	this->created = header->ts;
	this->touched = header->ts;
	this->npackets = 1;
	this->nbytes = header->len;
	this->options = 0;
	this->flow_type = type_unidentified;
	this->id_type = no_match;
}

pic_flow_s::
~pic_flow_s () {}

ostream & operator<< (ostream & stream, const pic_flow_s & o)
{
	stream << o.created.tv_sec << "." << o.created.tv_usec << ","
		<< o.touched.tv_sec << "." << o.touched.tv_usec << ","
		<< o.npackets << "," << o.nbytes << "," << int(o.flow_type);
	return(stream);
}


bool pic_flow_s::
operator== (const pic_flow_s & o)
{
	return (
		this->created.tv_sec == o.created.tv_sec &&
		this->created.tv_usec == o.created.tv_usec &&
		this->touched.tv_sec == o.touched.tv_sec &&
		this->touched.tv_usec == o.touched.tv_usec &&
		this->npackets == o.npackets && this->nbytes == o.nbytes &&
		this->options == o.options && this->flow_type == o.flow_type
	);
}


int pic_flow_s::
update (const pcap_pkthdr * header)
{
	this->touched = header->ts;
	this->npackets += 1;
	this->nbytes += header->len;
	return(EXIT_SUCCESS);
}

/*
 pic_ident_t
*/
pic_ident_s::
pic_ident_s ()
{
	struct timeval ts;
	ts.tv_sec = 0;
	ts.tv_usec = 0;
	this->touched = ts;
	this->certain = false;
}

pic_ident_s::
pic_ident_s (struct timeval ts, bool certain)
{
	this->touched = ts;
	this->certain = certain;
}

pic_ident_s::
~pic_ident_s () {}

int pic_ident_s::
update (struct timeval ts, bool certain)
{
	this->touched = ts;
	this->certain = certain;
	return(EXIT_SUCCESS);
}

ostream & operator<< (ostream & stream, const pic_ident_s & o)
{
	stream << o.touched.tv_sec << "." << o.touched.tv_usec << "," << o.certain;
	return (stream);
}

/*
 pic_stat_s
*/
pic_stat_s::
pic_stat_s ()
{
	this->nflows = 0;
	this->npackets = 0;
	this->nbytes = 0;
}

pic_stat_s::
pic_stat_s (pic_flow_s f)
{
	this->nflows = 1;
	this->npackets = f.npackets;
	this->nbytes = f.nbytes;
}

pic_stat_s::
~pic_stat_s () {}

int pic_stat_s::
update (pic_flow_s f)
{
	this->nflows++;
	this->npackets += f.npackets;
	this->nbytes += f.nbytes;
	return (EXIT_SUCCESS);
}

ostream & operator<< (ostream & stream, const pic_stat_s & o)
{
	stream 
		<< "packets: \x1b[33m" << setw(10) << o.npackets << "\x1b[0m "
		<< "bytes: \x1b[34m"<< setw(10) << o.nbytes << "\x1b[0m "
		<< "flows: \x1b[36m" << setw(10) << o.nflows << "\x1b[0m "
	;
	return (stream);
}
#endif //__cplusplus
