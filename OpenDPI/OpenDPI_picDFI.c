/*
 * OpenDPI_demo.c
 * Copyright (C) 2009 by ipoque GmbH
 * 
 * This file is part of OpenDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * OpenDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * OpenDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with OpenDPI.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */



#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h> // inet_ntop

#ifdef __linux__
# include <linux/ip.h>
# include <linux/tcp.h>
# include <linux/udp.h>
# include <linux/if_ether.h>
#else
# include "linux_compat.h"
#endif

#include <pcap.h>

#include <ipq_api.h>

// cli options
static char *_pcap_file = NULL;
// picdfi {
// for output file handling
static char *_out_file_name = NULL;
static FILE *_out_file_handle = NULL;
// picdfi }

// pcap
static char _pcap_error_buffer[PCAP_ERRBUF_SIZE];
static pcap_t *_pcap_handle = NULL;
static int _pcap_datalink_type = 0;

// detection
static struct ipoque_detection_module_struct *ipoque_struct = NULL;
static u32 detection_tick_resolution = 1000;
static char *prot_long_str[] = { IPOQUE_PROTOCOL_LONG_STRING };

#ifdef IPOQUE_ENABLE_DEBUG_MESSAGES
static char *prot_short_str[] = { IPOQUE_PROTOCOL_SHORT_STRING };

static IPOQUE_PROTOCOL_BITMASK debug_messages_bitmask;
#endif

// results
static u64 raw_packet_count = 0;
static u64 ip_packet_count = 0;
static u64 total_bytes = 0;
static u64 protocol_counter[IPOQUE_MAX_SUPPORTED_PROTOCOLS + 1];
static u64 protocol_counter_bytes[IPOQUE_MAX_SUPPORTED_PROTOCOLS + 1];


// id tracking
typedef struct osdpi_id {
	u8 ip[4];
	struct ipoque_id_struct *ipoque_id;
} osdpi_id_t;

static u32 size_id_struct = 0;
#define			MAX_OSDPI_IDS			500000
static struct osdpi_id *osdpi_ids;
static u32 osdpi_id_count = 0;

// picdfi {
#define PICDFI_TYPE_UNIDENTIFIED 0x00
#define PICDFI_TYPE_POSSIBLE 0x01
#define PICDFI_TYPE_P2P	0x02
#define PICDFI_TYPE_NONP2P 0x04
// picdfi }

// flow tracking
typedef struct osdpi_flow {
	u32 lower_ip;
	u32 upper_ip;
	u16 lower_port;
	u16 upper_port;
	u16 protocol;
	u16 picdfi_type;
	u32 detected_protocol;
	//u32 dummy; // Only here to align to 64 bits, in case the following pointer is 64 bits (to ensure consistent disk format between 32 and 64 bit architectures)
	// Serialisation will only write data before this pointer:
	struct ipoque_flow_struct *ipoque_flow;
} osdpi_flow_t;

static u32 size_flow_struct = 0;
#define			MAX_OSDPI_FLOWS			500000
static struct osdpi_flow *osdpi_flows;
static u32 osdpi_flow_count = 0;

#ifdef IPOQUE_ENABLE_DEBUG_MESSAGES
static int string_to_detection_bitmask(char *str, IPOQUE_PROTOCOL_BITMASK * dbm)
{
	u32 a;
	u32 oldptr = 0;
	u32 ptr = 0;
	IPOQUE_BITMASK_RESET(*dbm);

	printf("Protocol parameter given: %s\n", str);

	if (strcmp(str, "all") == 0) {
		printf("Protocol parameter all parsed\n");
		IPOQUE_BITMASK_SET_ALL(*dbm);
		printf("Bitmask is: " IPOQUE_BITMASK_DEBUG_OUTPUT_BITMASK_STRING " \n",
			   IPOQUE_BITMASK_DEBUG_OUTPUT_BITMASK_VALUE(*dbm));
		return 0;
	}
	// parse bitmask
	while (1) {
		if (str[ptr] == 0 || str[ptr] == ' ') {
			printf("Protocol parameter: parsed: %.*s,\n", ptr - oldptr, &str[oldptr]);
			for (a = 1; a <= IPOQUE_MAX_SUPPORTED_PROTOCOLS; a++) {

				if (strlen(prot_short_str[a]) == (ptr - oldptr) &&
					(memcmp(&str[oldptr], prot_short_str[a], ptr - oldptr) == 0)) {
					IPOQUE_ADD_PROTOCOL_TO_BITMASK(*dbm, a);
					printf("Protocol parameter detected as protocol %s\n", prot_long_str[a]);
				}
			}
			oldptr = ptr + 1;
			if (str[ptr] == 0)
				break;
		}
		ptr++;
	}
	return 0;
}
#endif

static void parseOptions(int argc, char **argv)
{
	int opt;

#ifdef IPOQUE_ENABLE_DEBUG_MESSAGES
	IPOQUE_BITMASK_SET_ALL(debug_messages_bitmask);
#endif

	while ((opt = getopt(argc, argv, "r:e:o:")) != EOF) {
		switch (opt) {
		case 'r':
			_pcap_file = optarg;
			break;
		case 'e':
#ifdef IPOQUE_ENABLE_DEBUG_MESSAGES
			// set debug logging bitmask to all protocols
			if (string_to_detection_bitmask(optarg, &debug_messages_bitmask) != 0) {
				printf("ERROR option -e needs a valid list of protocols");
				exit(-1);
			}

			printf("debug messages Bitmask is: " IPOQUE_BITMASK_DEBUG_OUTPUT_BITMASK_STRING "\n",
				   IPOQUE_BITMASK_DEBUG_OUTPUT_BITMASK_VALUE(debug_messages_bitmask));

#else
			printf("ERROR: option -e : DEBUG MESSAGES DEACTIVATED\n");
			exit(-1);
#endif
			break;
		case 'o':
			_out_file_name = optarg;
		}
	}

	// check parameters
	if (_pcap_file == NULL || strcmp(_pcap_file, "") == 0) {
		printf("ERROR: no pcap file path provided; use option -r with the path to a valid pcap file\n");
		exit(-1);
	}
}

static void debug_printf(u32 protocol, void *id_struct, ipq_log_level_t log_level, const char *format, ...)
{
#ifdef IPOQUE_ENABLE_DEBUG_MESSAGES
	if (IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(debug_messages_bitmask, protocol) != 0) {
		const char *protocol_string;
		const char *file;
		const char *func;
		u32 line;
		va_list ap;
		va_start(ap, format);

		protocol_string = prot_short_str[protocol];

		ipoque_debug_get_last_log_function_line(ipoque_struct, &file, &func, &line);

		printf("\nDEBUG: %s:%s:%u Prot: %s, level: %u packet: %llu :", file, func, line, protocol_string,
			   log_level, raw_packet_count);
		vprintf(format, ap);
		va_end(ap);
	}
#endif
}

static void *malloc_wrapper(unsigned long size)
{
	return malloc(size);
}

static void free_wrapper(void *freeable)
{
	free(freeable);
}

static void *get_id(const u8 * ip)
{
	u32 i;
	for (i = 0; i < osdpi_id_count; i++) {
		if (memcmp(osdpi_ids[i].ip, ip, sizeof(u8) * 4) == 0) {
			return osdpi_ids[i].ipoque_id;
		}
	}
	if (osdpi_id_count == MAX_OSDPI_IDS) {
		printf("ERROR: maximum unique id count (%u) has been exceeded\n", MAX_OSDPI_IDS);
		exit(-1);
	} else {
		struct ipoque_id_struct *ipoque_id;
		memcpy(osdpi_ids[osdpi_id_count].ip, ip, sizeof(u8) * 4);
		ipoque_id = osdpi_ids[osdpi_id_count].ipoque_id;

		osdpi_id_count += 1;
		return ipoque_id;
	}
}

static struct osdpi_flow *get_osdpi_flow(const struct iphdr *iph, u16 ipsize)
{
	u32 i;
	u16 l4_packet_len;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	u32 lower_ip;
	u32 upper_ip;
	u16 lower_port;
	u16 upper_port;

	if (ipsize < 20)
		return NULL;

	if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
		|| (iph->frag_off & htons(0x1FFF)) != 0)
		return NULL;

	l4_packet_len = ntohs(iph->tot_len) - (iph->ihl * 4);

	if (iph->saddr < iph->daddr) {
		lower_ip = iph->saddr;
		upper_ip = iph->daddr;
	} else {
		lower_ip = iph->daddr;
		upper_ip = iph->saddr;
	}

	if (iph->protocol == 6 && l4_packet_len >= 20) {
		// tcp
		tcph = (struct tcphdr *) ((u8 *) iph + iph->ihl * 4);
		if (iph->saddr < iph->daddr) {
			lower_port = tcph->source;
			upper_port = tcph->dest;
		} else {
			lower_port = tcph->dest;
			upper_port = tcph->source;
		}
	} else if (iph->protocol == 17 && l4_packet_len >= 8) {
		// udp
		udph = (struct udphdr *) ((u8 *) iph + iph->ihl * 4);
		if (iph->saddr < iph->daddr) {
			lower_port = udph->source;
			upper_port = udph->dest;
		} else {
			lower_port = udph->dest;
			upper_port = udph->source;
		}
	} else {
		// non tcp/udp protocols
		lower_port = 0;
		upper_port = 0;
	}

	for (i = 0; i < osdpi_flow_count; i++) {
		if (osdpi_flows[i].protocol == iph->protocol &&
			osdpi_flows[i].lower_ip == lower_ip &&
			osdpi_flows[i].upper_ip == upper_ip &&
			osdpi_flows[i].lower_port == lower_port && osdpi_flows[i].upper_port == upper_port) {
			return &osdpi_flows[i];
		}
	}
	if (osdpi_flow_count == MAX_OSDPI_FLOWS) {
		printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_OSDPI_FLOWS);
		exit(-1);
	} else {
		struct osdpi_flow *flow;
		osdpi_flows[osdpi_flow_count].protocol = iph->protocol;
		osdpi_flows[osdpi_flow_count].lower_ip = lower_ip;
		osdpi_flows[osdpi_flow_count].upper_ip = upper_ip;
		osdpi_flows[osdpi_flow_count].lower_port = lower_port;
		osdpi_flows[osdpi_flow_count].upper_port = upper_port;
		flow = &osdpi_flows[osdpi_flow_count];

		osdpi_flow_count += 1;
		return flow;
	}
}

static void setupDetection(void)
{
	u32 i;
	IPOQUE_PROTOCOL_BITMASK all;

	// init global detection structure
	ipoque_struct = ipoque_init_detection_module(detection_tick_resolution, malloc_wrapper, debug_printf);
	if (ipoque_struct == NULL) {
		printf("ERROR: global structure initialization failed\n");
		exit(-1);
	}
	// enable all protocols
	IPOQUE_BITMASK_SET_ALL(all);
	ipoque_set_protocol_detection_bitmask2(ipoque_struct, &all);

	// allocate memory for id and flow tracking
	size_id_struct = ipoque_detection_get_sizeof_ipoque_id_struct();
	size_flow_struct = ipoque_detection_get_sizeof_ipoque_flow_struct();

	osdpi_ids = malloc(MAX_OSDPI_IDS * sizeof(struct osdpi_id));
	if (osdpi_ids == NULL) {
		printf("ERROR: malloc for osdpi_ids failed\n");
		exit(-1);
	}
	for (i = 0; i < MAX_OSDPI_IDS; i++) {
		memset(&osdpi_ids[i], 0, sizeof(struct osdpi_id));
		osdpi_ids[i].ipoque_id = calloc(1, size_id_struct);
		if (osdpi_ids[i].ipoque_id == NULL) {
			printf("ERROR: malloc for ipoque_id_struct failed\n");
			exit(-1);
		}
	}

	osdpi_flows = malloc(MAX_OSDPI_FLOWS * sizeof(struct osdpi_flow));
	if (osdpi_flows == NULL) {
		printf("ERROR: malloc for osdpi_flows failed\n");
		exit(-1);
	}
	for (i = 0; i < MAX_OSDPI_FLOWS; i++) {
		memset(&osdpi_flows[i], 0, sizeof(struct osdpi_flow));
		osdpi_flows[i].ipoque_flow = calloc(1, size_flow_struct);
		if (osdpi_flows[i].ipoque_flow == NULL) {
			printf("ERROR: malloc for ipoque_flow_struct failed\n");
			exit(-1);
		}
	}

	// clear memory for results
	memset(protocol_counter, 0, (IPOQUE_MAX_SUPPORTED_PROTOCOLS + 1) * sizeof(u64));
	memset(protocol_counter_bytes, 0, (IPOQUE_MAX_SUPPORTED_PROTOCOLS + 1) * sizeof(u64));
}

static void terminateDetection(void)
{
	u32 i;

	ipoque_exit_detection_module(ipoque_struct, free_wrapper);

	for (i = 0; i < MAX_OSDPI_IDS; i++) {
		free(osdpi_ids[i].ipoque_id);
	}
	free(osdpi_ids);
	for (i = 0; i < MAX_OSDPI_FLOWS; i++) {
		free(osdpi_flows[i].ipoque_flow);
	}
	free(osdpi_flows);
}

static unsigned int packet_processing(const uint64_t time, const struct iphdr *iph, uint16_t ipsize, uint16_t rawsize)
{
	struct ipoque_id_struct *src = NULL;
	struct ipoque_id_struct *dst = NULL;
	struct osdpi_flow *flow = NULL;
	struct ipoque_flow_struct *ipq_flow = NULL;
	u32 protocol = 0;


	src = get_id((u8 *) & iph->saddr);
	dst = get_id((u8 *) & iph->daddr);

	flow = get_osdpi_flow(iph, ipsize);
	if (flow != NULL) {
		ipq_flow = flow->ipoque_flow;
	}

	ip_packet_count++;
	total_bytes += rawsize;

#ifndef IPOQUE_ENABLE_DEBUG_MESSAGES
	if (ip_packet_count % 499 == 0) {
		printf("\rip packets scanned: \x1b[33m%-10llu\x1b[0m ip bytes scanned: \x1b[34m%-10llu\x1b[0m",
			   ip_packet_count, total_bytes);
	}
#endif

	// only handle unfragmented packets
	if ((iph->frag_off & htons(0x1FFF)) == 0) {

		// here the actual detection is performed
		protocol = ipoque_detection_process_packet(ipoque_struct, ipq_flow, (uint8_t *) iph, ipsize, time, src, dst);

	} else {
		static u8 frag_warning_used = 0;
		if (frag_warning_used == 0) {
			printf("\n\nWARNING: fragmented ip packets are not supported and will be skipped \n\n");
			sleep(2);
			frag_warning_used = 1;
		}
		return 0;
	}

	protocol_counter[protocol]++;
	protocol_counter_bytes[protocol] += rawsize;

	if (flow != NULL) {
		flow->detected_protocol = protocol;
	}

	return 0;
}

static void printResults(void)
{
	u32 i;

	printf("\x1b[2K\n");
	printf("pcap file contains\n");
	printf("\tip packets:   \x1b[33m%-13llu\x1b[0m of %llu packets total\n", ip_packet_count, raw_packet_count);
	printf("\tip bytes:     \x1b[34m%-13llu\x1b[0m\n", total_bytes);
	printf("\tunique ids:   \x1b[35m%-13u\x1b[0m\n", osdpi_id_count);
	printf("\tunique flows: \x1b[36m%-13u\x1b[0m\n", osdpi_flow_count);

	printf("\n\ndetected protocols:\n");
	for (i = 0; i <= IPOQUE_MAX_SUPPORTED_PROTOCOLS; i++) {
		u32 protocol_flows = 0;
		u32 j;

		// count flows for that protocol
		for (j = 0; j < osdpi_flow_count; j++) {
			if (osdpi_flows[j].detected_protocol == i) {
				protocol_flows++;
			}
		}

		if (protocol_counter[i] > 0) {
			printf("\t\x1b[31m%-20s\x1b[0m packets: \x1b[33m%-13llu\x1b[0m bytes: \x1b[34m%-13llu\x1b[0m "
				   "flows: \x1b[36m%-13u\x1b[0m\n",
				   prot_long_str[i], protocol_counter[i], protocol_counter_bytes[i], protocol_flows);
		}
	}
	printf("\n\n");
}

static void openPcapFile(void)
{
	_pcap_handle = pcap_open_offline(_pcap_file, _pcap_error_buffer);

	if (_pcap_handle == NULL) {
		printf("ERROR: could not open pcap file: %s\n", _pcap_error_buffer);
		exit(-1);
	}
	_pcap_datalink_type = pcap_datalink(_pcap_handle);
}

static void closePcapFile(void)
{
	if (_pcap_handle != NULL) {
		pcap_close(_pcap_handle);
	}
}

// picdfi {
static void openOutputFile (void)
{
	if (_out_file_name != NULL) {
		_out_file_handle = fopen(_out_file_name,"w");
		if (_out_file_handle == NULL) {
			fprintf(stderr, "ERROR: could not open output file: %s: %s\n", _out_file_name, strerror(errno));
		}
	} else {
		fprintf(stderr, "No file name provided\n");
	}
}

static int closeOutputFile (void)
{
	int ret = 0;
	if (_out_file_handle != NULL) {
		ret = fclose(_out_file_handle);
		if (ret != 0) {
			printf("ERROR: could not close output file: %d\n", ret);
		}	
	}
	return ret;
}

/*
 serializeResults
 write the flows to an output file.
 format of the output file is as follows:
 lower_ip, lower_port, upper_ip, upper_port, protocol, created ts, touched ts, npackets, nbytes, pic flow type
 i couldn't find any information regarding timestamps or number of packets/bytes, so we set these to 0
 maybe we include this in osdpi_flow and detection here, if possible
*/
static int serializeResults (void)
{
	int ret = 0;
	int i, count;
	struct osdpi_flow *of;
	// Write osdpi_flow_count flows to the file, but only the bytes up to the pointer (ipoque_flow)
	if (_out_file_handle != NULL) {
		count = 0;
		for (i = 0; i < osdpi_flow_count; i++) {
			of = &osdpi_flows[i];
			char lower_ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(of->lower_ip), lower_ip, INET_ADDRSTRLEN);
			char upper_ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(of->upper_ip), upper_ip, INET_ADDRSTRLEN);
			// don't have info on timestamps etc, set to zero
			fprintf(_out_file_handle, "%s,%d,%s,%d,%d,0.0,0.0,0,0,%d\n",lower_ip,ntohs(of->lower_port),upper_ip,ntohs(of->upper_port),(int)of->protocol,(int)of->picdfi_type);
		}
	}
	return ret;
}

// converts OpenDPI protocol classes to picDFI flow classes
static void convertResults (void)
{
	int i = 0;
	for (i = 0; i < osdpi_flow_count; i++) {
		switch (osdpi_flows[i].detected_protocol) {
		case IPOQUE_PROTOCOL_UNKNOWN:
			osdpi_flows[i].picdfi_type = PICDFI_TYPE_UNIDENTIFIED;
			break;
		case IPOQUE_PROTOCOL_FTP:
		case IPOQUE_PROTOCOL_MAIL_POP:
		case IPOQUE_PROTOCOL_MAIL_SMTP:
		case IPOQUE_PROTOCOL_MAIL_IMAP:
		case IPOQUE_PROTOCOL_DNS:
		case IPOQUE_PROTOCOL_IPP:
		case IPOQUE_PROTOCOL_HTTP:
		case IPOQUE_PROTOCOL_MDNS:
		case IPOQUE_PROTOCOL_NTP:
		case IPOQUE_PROTOCOL_NETBIOS:
		case IPOQUE_PROTOCOL_NFS:
		case IPOQUE_PROTOCOL_SSDP:
		case IPOQUE_PROTOCOL_BGP:
		case IPOQUE_PROTOCOL_SNMP:
		case IPOQUE_PROTOCOL_XDMCP:
		case IPOQUE_PROTOCOL_SMB:
		case IPOQUE_PROTOCOL_SYSLOG:
		case IPOQUE_PROTOCOL_DHCP:
		case IPOQUE_PROTOCOL_POSTGRES:
		case IPOQUE_PROTOCOL_MYSQL:
		case IPOQUE_PROTOCOL_TDS:
		case IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK:
		case IPOQUE_PROTOCOL_I23V5:
		case IPOQUE_PROTOCOL_SOCRATES:
 		case IPOQUE_PROTOCOL_AVI:
 		case IPOQUE_PROTOCOL_FLASH:
 		case IPOQUE_PROTOCOL_OGG:
		case IPOQUE_PROTOCOL_MPEG:
		case IPOQUE_PROTOCOL_QUICKTIME:
		case IPOQUE_PROTOCOL_REALMEDIA:
		case IPOQUE_PROTOCOL_WINDOWSMEDIA:
		case IPOQUE_PROTOCOL_MMS:
		case IPOQUE_PROTOCOL_XBOX:
		case IPOQUE_PROTOCOL_QQ:
		case IPOQUE_PROTOCOL_RTSP:
 		case IPOQUE_PROTOCOL_IRC:
 		case IPOQUE_PROTOCOL_UNENCRYPED_JABBER:
 		case IPOQUE_PROTOCOL_MSN:
 		case IPOQUE_PROTOCOL_YAHOO:
 		case IPOQUE_PROTOCOL_BATTLEFIELD:
 		case IPOQUE_PROTOCOL_QUAKE:
 		case IPOQUE_PROTOCOL_SECONDLIFE:
 		case IPOQUE_PROTOCOL_POPO:
 		case IPOQUE_PROTOCOL_HALFLIFE2:
 		case IPOQUE_PROTOCOL_WORLDOFWARCRAFT:
 		case IPOQUE_PROTOCOL_TELNET:
 		case IPOQUE_PROTOCOL_STUN:
 		case IPOQUE_PROTOCOL_IPSEC:
 		case IPOQUE_PROTOCOL_GRE:
 		case IPOQUE_PROTOCOL_ICMP:
 		case IPOQUE_PROTOCOL_IGMP:
 		case IPOQUE_PROTOCOL_EGP:
 		case IPOQUE_PROTOCOL_SCTP:
 		case IPOQUE_PROTOCOL_OSPF:
 		case IPOQUE_PROTOCOL_IP_IN_IP:
		case IPOQUE_PROTOCOL_RTP:
 		case IPOQUE_PROTOCOL_RDP:
 		case IPOQUE_PROTOCOL_VNC:
 		case IPOQUE_PROTOCOL_PCANYWHERE:
 		case IPOQUE_PROTOCOL_SSL:
 		case IPOQUE_PROTOCOL_SSH:
 		case IPOQUE_PROTOCOL_USENET:
 		case IPOQUE_PROTOCOL_MGCP:
 		case IPOQUE_PROTOCOL_IAX:
 		case IPOQUE_PROTOCOL_TFTP:
 		case IPOQUE_PROTOCOL_AFP:
 		case IPOQUE_PROTOCOL_STEALTHNET:
 		case IPOQUE_PROTOCOL_ICECAST:
 		case IPOQUE_PROTOCOL_SHOUTCAST:
 		case IPOQUE_PROTOCOL_GADUGADU:
		case IPOQUE_PROTOCOL_MOVE:
 		//case IPOQUE_PROTOCOL_VEOHTV:
 		case IPOQUE_PROTOCOL_STEAM:
 		case IPOQUE_PROTOCOL_OSCAR:
			osdpi_flows[i].picdfi_type = PICDFI_TYPE_NONP2P;
			break;
		case IPOQUE_PROTOCOL_APPLEJUICE:
		case IPOQUE_PROTOCOL_DIRECTCONNECT:
 		case IPOQUE_PROTOCOL_WINMX:
 		case IPOQUE_PROTOCOL_MANOLITO:
 		case IPOQUE_PROTOCOL_PANDO:
		case IPOQUE_PROTOCOL_IMESH:
 		case IPOQUE_PROTOCOL_FASTTRACK:
 		case IPOQUE_PROTOCOL_GNUTELLA:
 		case IPOQUE_PROTOCOL_EDONKEY:
 		case IPOQUE_PROTOCOL_BITTORRENT:
 		case IPOQUE_PROTOCOL_SOULSEEK:
 		case IPOQUE_PROTOCOL_THUNDER:
		case IPOQUE_PROTOCOL_KONTIKI:
 		case IPOQUE_PROTOCOL_OPENFT:
 		case IPOQUE_PROTOCOL_OFF:
 		case IPOQUE_PROTOCOL_FILETOPIA:
 		case IPOQUE_PROTOCOL_AIMINI:
		case IPOQUE_PROTOCOL_PPLIVE:
 		//case IPOQUE_PROTOCOL_ZATOO:
 		case IPOQUE_PROTOCOL_PPSTREAM:
 		case IPOQUE_PROTOCOL_FEIDIAN:
 		case IPOQUE_PROTOCOL_QQLIVE:
 		case IPOQUE_PROTOCOL_TVUPLAYER:
 		case IPOQUE_PROTOCOL_SOPCAST:
 		case IPOQUE_PROTOCOL_TVANTS:
			osdpi_flows[i].picdfi_type = PICDFI_TYPE_P2P;
 			break;
		}	
	}
}
// picdfi }

// executed for each packet in the pcap file
// callback function has been completely rewritten to support raw ip format
static void pcap_packet_callback(u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
	raw_packet_count++;
	// check the time
	u64 time;
	static u64 lasttime = 0;
	time = ((uint64_t) header->ts.tv_sec) * detection_tick_resolution +
		header->ts.tv_usec / (1000000 / detection_tick_resolution);
	if (lasttime > time) {
		// printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", lasttime - time);
		time = lasttime;
	}
	lasttime = time;
	// check caplen and len of pcap_pkthdr
	if (header->caplen < header->len) {
		static u8 cap_warning_used = 0;
		if (cap_warning_used == 0) {
			printf ("\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY OR EVEN CRASH\n\n");
			sleep(1);
			cap_warning_used = 1;
		}
	}

	static u8 dlt_warning_used = 0;	
	if (dlt_warning_used == 0) {
		printf("\n\nDLT: %d found\n", _pcap_datalink_type);
		dlt_warning_used = 1;
	}	
	
	struct iphdr *iph = NULL;
	size_t size = 0;

	// depending on the datalink type we have to do different disecting
	// if we got ethernet link, adjust pointers accordingly
	if (_pcap_datalink_type == DLT_EN10MB && header->caplen >= sizeof(struct ethhdr)) {
		// prepare packet pointers
		const struct ethhdr *ethernet = (struct ethhdr *) packet;
		iph = (struct iphdr *) &packet[sizeof(struct ethhdr)];
		size = header->len - sizeof(struct ethhdr);
		// check ethernet type
		if (ethernet->h_proto != htons(ETH_P_IP)) {
			static u8 eth_warning_used = 0;
			if (eth_warning_used == 0) {
				printf("\n\nWARNING: only ethernet IP packets are supported\n\n");
				sleep(1);
				eth_warning_used = 1;
			}
			return;
		}
	}
	// support for raw IP datalink format
	else if (_pcap_datalink_type == DLT_RAW && header->caplen >= sizeof(struct iphdr)) {
		iph = (struct iphdr *) packet;
		size = header->len;
	}
	// support for chdlc datalink format
	else if (_pcap_datalink_type == DLT_C_HDLC && header->caplen >= 4) {
		iph = (struct iphdr *) &packet[4];
		size = header->len - 4;
	}
	
	// check ip type
	if (iph->version != 4) {
		static u8 ipv4_warning_used = 0;
		if (ipv4_warning_used == 0) {
			printf("\n\nWARNING: only IPv4 packets are supported, all other packets will be discarded\n\n");
			sleep(1);
			ipv4_warning_used = 1;
		}
		return;
	}
	// process the packet
	packet_processing(time, iph, size, header->len);
}

static void runPcapLoop(void)
{
	if (_pcap_handle != NULL) {
		pcap_loop(_pcap_handle, -1, &pcap_packet_callback, NULL);
	}
}

// this is never called, just here for debugging
static void printSizes (void)
{
	printf("osdpi_flow: %ld\n", sizeof(struct osdpi_flow));
	printf("u32: %ld\n", sizeof(u32));
	printf("u16: %ld\n", sizeof(u16));
	printf("u8: %ld\n", sizeof(u8));
	printf("ipoque_flow_struct*: %ld\n", sizeof(struct ipoque_flow_struct *));
}
 
int main(int argc, char **argv)
{
	time_t start, stop;
	parseOptions(argc, argv);

	setupDetection();

	openPcapFile();
	start = time(NULL);
	runPcapLoop();
	stop = time(NULL);
	closePcapFile();

	printf("\nprocessed in %ld secs\n",(long)stop-start);
	printResults();
	
	// picdfi {
	openOutputFile();
	convertResults();
	serializeResults();
	closeOutputFile();
	// picdfi }

	terminateDetection();

	return 0;
}
