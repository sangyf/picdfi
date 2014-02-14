/*
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
 *
 *  tables.h
 *  picflow
 *
 *  Created by Thomas Zink on 3/12/10.
 *
 */

#ifndef _TABLES_H_
#define _TABLES_H_

#include <map>
#include <pcap.h>
#include "flow.h"

typedef map<pic_connection_s,pic_flow_s> flow_table_t;
typedef pair<pic_connection_s,pic_flow_s> flow_table_entry_t;
typedef map<pic_service_s,pic_ident_s> identification_table_t;
typedef pair<pic_service_s,pic_ident_s> identification_table_entry_t;
typedef map<picdfi_type,pic_stat_s> statistic_table_t;
typedef map<pic_connection_s,pic_flow_s> verification_table_t;
typedef pair<pic_connection_s,pic_flow_s> verification_table_entry_t;
typedef map<verification_type,pic_stat_s> vstat_table_t;

void init_statistics (void);
pair<flow_table_t::iterator,bool> flow_table_update (u_char * args, const struct pcap_pkthdr *header, const u_char * ippacket);
identification_type identify_flow (flow_table_t::iterator it_flows, const u_int16_t dport, const u_char * payload);
void update_flow (flow_table_t::iterator it_flows, bool certain);
void do_ageing (const struct pcap_pkthdr *header, flow_handler_f callback);
void flush_flows (flow_handler_f callback);
void print_statistics (void);
void print_details (void);

#endif // _TABLES_H_
