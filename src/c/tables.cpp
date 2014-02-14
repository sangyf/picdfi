/*
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
 *
 *  tables.cpp
 *  picflow
 *
 *  Created by Thomas Zink on 3/12/10.
 *
 */

//#include "app.h"
#include "defines.h"
#include <iostream>
#include "tables.h"
#include "optpar.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>

extern optarg_t * optargs;

// tables
flow_table_t flows;					// flow table
identification_table_t services;	// identification table
statistic_table_t statistics;		// calcultaing flow stats
verification_table_t verify;		// verification table
vstat_table_t vstats;				// calc verification stats
pic_stat_s total_flows;

// just for progress
u_int32_t ip_packets_scanned = 0;
u_int32_t ip_bytes_scanned = 0;
long last_aged = 0;

/*
 payload matching
 got a problem with the following characters:
 \xe3 : displayed as ffffffe3
 \xc5 : displayed as ffffffc5
 \x00 : is the null termination string,
 terminates all string cpy/cmp functions
 so these are out of the question.
 we use memcmp instead.
*/
const char *signatures[] = {
	"\x13""Bit","d1:a","d1:r","d1:e",
	"GNUT","GIV ","GND ","GO!!","MD5 ",
	"\x27\x00\x00\x00","\xe3\x19\x01\x00","\xc5\x3f\x01\x00"
};

/*
 port matching
 not yet implemented
 only list of well known P2P ports
*/
const int ports[] = {
	6346,6347, // limewire, morpheus, bearshare
	4662,4672, // ed2k
	6881,6882,6883,6884,6885,6886,6887,6888,6889,6890, // bittorrent
	6969,	// bittorrent tracker
	6699,6257 // winmx
};

const size_t sig_num = 12;
const size_t sig_size = 4;


void
init_statistics (void)
{
	statistics[type_unidentified] = pic_stat_s();
	statistics[type_possible] = pic_stat_s();
	statistics[type_p2p] = pic_stat_s();
	statistics[type_nonp2p] = pic_stat_s();
	vstats[na_positive] = pic_stat_s();
	if (optargs->vfile != NULL) {
		vstats[na_negative] = pic_stat_s();
		vstats[true_positive] = pic_stat_s();
		vstats[false_negative] = pic_stat_s();
		vstats[true_negative] = pic_stat_s();
		vstats[false_negative] = pic_stat_s();
	}
}

pair<flow_table_t::iterator,bool>
flow_table_update (u_char * args, const struct pcap_pkthdr * header, const u_char * ippacket)
{
	pair<flow_table_t::iterator,bool> ret;
	pic_connection_t flowid (ippacket);
	pic_flow_t flow (header);
#if DEBUG >= 2
	cout << "(flow ID) " << flowid << endl;
#endif
	ret = flows.insert(flow_table_entry_t (flowid,flow));
	if (ret.second==false) {
		ret.first->second.update(header);
#if DEBUG >= 2
		cout << "(flow update) "
		<< ret.first->first << " : " 
		<< ret.first->second << " size: " << flows.size()
		<< endl;
#endif
	} else {
		total_flows.nflows++;
#if DEBUG >= 2
		cout << "(flow new) "
		<< ret.first->first << " : "
		<< ret.first->second << " size: " << flows.size()
		<< endl;
#endif
	}
	
#if ASSERT == 1
	// check integrity
	flow_table_t::iterator it;
	it = flows.find(flowid);
	assert (it != flows.end());
#endif
	
	total_flows.npackets++;
	total_flows.nbytes += header->len;
	return(ret);
}

identification_type
identify_flow (flow_table_t::iterator it_flows, const u_char * payload)
{
	identification_table_t::iterator it_lower;
	identification_table_t::iterator it_upper;
	bool recent_lower, recent_upper, certain_lower, certain_upper;
	recent_lower = recent_upper = certain_lower = certain_upper = false;
	
	// first check the payload
	// if we find a signature, it's certain P2P
	uint i;
	for (i=0; i<sig_num; i++) {
		if (memcmp(payload,signatures[i],4) == 0) {
#if DEBUG >= 2
			cout << "payload_match " << payload << "\n";
#endif
			update_flow(it_flows, true);
			return (payload_match);
		}
	}
	
	// get {recent,certain}_{lower,upper}
	it_lower = services.find(*(it_flows->first.lower));
	it_upper = services.find(*(it_flows->first.upper));
	//struct timeval tv_delta;
	if (it_lower != services.end()) {
		certain_lower = it_lower->second.certain;
		long delta = abs(it_flows->second.touched.tv_sec - it_lower->second.touched.tv_sec);
		recent_lower = certain_lower ? delta <= optargs->t_long : delta <= optargs->t_short;
	}
	if (it_upper != services.end()) {
		certain_lower = it_upper->second.certain;
		long delta = abs(it_flows->second.touched.tv_sec - it_upper->second.touched.tv_sec);
		recent_lower = certain_lower ? delta <= optargs->t_long : delta <= optargs->t_short;
	}
	
#if DEBUG >= 2
	cout << "(recent_certain) " 
		<< recent_lower << certain_lower
		<< recent_upper << certain_upper << endl;
#endif
	// protocol dependent identification
	if (it_flows->first.ip_p == IPPROTO_TCP) {
		if (recent_lower || recent_upper) {
#if DEBUG >= 2
			cout << "tcp_certain\n";
#endif
			update_flow(it_flows, true);
			return (tcp_certain);
		}
		else {
			//it_flows->second.flow_type = PICDFI_TYPE_NONP2P;
#if DEBUG >= 2
			cout << "tcp_none\n";
#endif			
			return (tcp_none);
		}
	}
	
	if (it_flows->first.ip_p == IPPROTO_UDP) {
		if ((recent_lower && certain_lower) || (recent_upper && certain_upper)) {
#if DEBUG >= 2
			cout << "udp_certain\n";
#endif			
			update_flow(it_flows, true);
			return (udp_certain);
		}
#if DEBUG >= 2
		cout << "udp_uncertain\n";
#endif		
		update_flow(it_flows, false);
		return (udp_uncertain);
	}
	
	// if we reach this point, we can't identify the flow as P2P
#if DEBUG >= 2
	cout << "no_match\n";
#endif	
	//it_flows->second.flow_type = PICDFI_TYPE_NONP2P;
	it_flows->second.flow_type = type_nonp2p;
	return (no_match);
}

void
update_flow (flow_table_t::iterator it_flows, bool certain)
{
	// somehow the following did not work
	//services[*(it_flows->first.lower)] = pic_ident_t (it_flows->second.touched,certain);
	//services[*(it_flows->first.upper)] = pic_ident_t (it_flows->second.touched,certain);
	// created unallocated objects
	// lead to segfaults during aging under certain circumstances, see do_ageing()
	pair<identification_table_t::iterator,bool> ret_lower;
	pair<identification_table_t::iterator,bool> ret_upper;
	pic_ident_t ident (it_flows->second.touched,certain);
	
	ret_lower = services.insert(identification_table_entry_t (*it_flows->first.lower,ident));
	ret_upper = services.insert(identification_table_entry_t (*it_flows->first.upper,ident));
	if (ret_lower.second==false) {
		ret_lower.first->second.touched = ident.touched;
		ret_lower.first->second.certain = certain;
#if DEBUG >= 2
		cout << "(lower service upd) "
			<< ret_lower.first->first << " : " << ret_lower.first->second << endl;
	} else {
		cout << "(lower service new) "
			<< ret_lower.first->first << " : " << ret_lower.first->second << endl;
#endif
	}

	if (ret_upper.second==false) {
		ret_upper.first->second.touched = ident.touched;
		ret_upper.first->second.certain = certain;
#if DEBUG >= 2
		cout << "(upper service upd) "
			<< ret_upper.first->first << " : " << ret_upper.first->second << endl;
	} else {
		cout << "(upper service new) "
			<< ret_upper.first->first << " : " << ret_upper.first->second << endl;
#endif
	}
	//it_flows->second.flow_type = certain ? PICDFI_TYPE_P2P : PICDFI_TYPE_POSSIBLE;
	it_flows->second.flow_type = certain ? type_p2p : type_possible;
#if DEBUG >= 2
	cout << "(size services) " << services.size() << endl;
#endif
}

void
do_ageing (const struct pcap_pkthdr *header, flow_handler_f callback)
{
	// age the flow table
	flow_table_t::iterator it_flows;
	for (it_flows=flows.begin(); it_flows!=flows.end(); ++it_flows) {
		if ((header->ts.tv_sec - it_flows->second.touched.tv_sec) > optargs->t_age) {
			//statistics[it_flows->second.flow_type].update(it_flows->second);
#if DEBUG == -1
			cout << it_flows->first << " : " << it_flows->second << endl;
#endif
#if DEBUG >= 2
			cout << "(flow erase) " << it_flows->first << " : " << it_flows->second << endl;
#endif
			callback (it_flows->first, it_flows->second);
			flows.erase(it_flows);
		}
	}
	// age the service table
	// dky, did lead to segmentation faults under following conditions
	// pic_service::operator< tests ports and NO DEBUG in update_flow
	// sample output: (service erase) 134.34.10.38,2405 : 0.-1403111106,0
	// happens after and before fow table aging
	// see update_flow for further info
#if AGE_SERVICE_TABLE == 1
	identification_table_t::iterator it_services;
	for (it_services=services.begin(); it_services!=services.end(); ++it_services) {
		// need to do individual aging for certain / uncertain
		long t = it_services->second.certain ? optargs->t_long : optargs->t_short;
		if ((header->ts.tv_sec - it_services->second.touched.tv_sec) > t) {
#if DEBUG >= 2
			cout << "(service erase) "
				<< it_services->first << " : "
				<< it_services->second << endl;
#endif
			services.erase(it_services);
		}
	}
#endif	
}

void
flush_flows (flow_handler_f callback)
{
	flow_table_t::iterator it_flows;
	for (it_flows=flows.begin(); it_flows!=flows.end(); ++it_flows) {
		callback (it_flows->first, it_flows->second);
		flows.erase(it_flows);
	}
}

void
print_statistics (void)
{
	cout << "Flow Table Summary\n";
	cout << "\x1b[31mTOTAL\x1b[0m\t\t" << total_flows << endl;
	statistic_table_t::iterator it_stats;
	for (it_stats=statistics.begin(); it_stats!=statistics.end(); ++it_stats) {
		switch (it_stats->first) {
			case type_unidentified:
				cout << "\x1b[31mUNIDENTIFIED\x1b[0m\t";
				break;
			case type_possible:
				cout << "\x1b[31mPOSSIBLE\x1b[0m\t";
				break;
			case type_p2p:
				cout << "\x1b[31mP2P\x1b[0m\t\t";
				break;
			case type_nonp2p:
				cout << "\x1b[31mNON P2P\x1b[0m\t\t";
				break;
			default:
				break;
		}
		cout << it_stats->second << "\n";
	}
	if (optargs->vfile != NULL) {
		cout << "Verification Summary\n";
		vstat_table_t::iterator it_vstats;
		for (it_vstats=vstats.begin(); it_vstats!=vstats.end(); ++it_vstats) {
			switch (it_vstats->first) {
				case na_positive:
					cout << "\x1b[31mNP\x1b[0m\t";
					break;
				case na_negative:
					cout << "\x1b[31mNN\x1b[0m\t";
					break;
				case true_positive:
					cout << "\x1b[31mTP\x1b[0m\t";
					break;
				case false_positive:
					cout << "\x1b[31mFP\x1b[0m\t";
					break;
				case true_negative:
					cout << "\x1b[31mTN\x1b[0m\t";
					break;
				case false_negative:
					cout << "\x1b[31mFN\x1b[0m\t";
					break;
				default:
					break;
			}
			cout << it_vstats->second << "\n";
		}
	}
}

void
print_details (void)
{
	cout << "Flow Table Details\n";
	flow_table_t::iterator it_flows;
	for (it_flows=flows.begin(); it_flows!=flows.end(); ++it_flows) {
			cout << "\t" << it_flows->first << " : " << it_flows->second << endl;
	}
}
