/*
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
 *
*/
/* includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>			// for string functions
#include <time.h>
#include <pcap.h>			// pcap packet capturing
#include <sys/socket.h>		// inet_* functions
#include <map>				// c++ map
#include <iostream>			// c++ cout
#include <signal.h>			// signal handling
#include <setjmp.h>			// jumps
#include "protocols.h"		// supported protocol structures and typedefs
#include "flow.h"			// flow, identification, statistics table structures
#include "handler.h"		// packet handler functions for pcap callback
#include "defines.h"		// info about this app and global defines
#include "optpar.h"			// options parser
#include "tables.h"			// all the table stuff
#include <unistd.h>			// geteuid
//#include <sys/types.h>


using namespace std;


/*
 prototypes
*/
int sniff (optarg_t *optargs);
void signal_handler (int sig);
void print_banner (void);

/*
 globals
*/
optarg_t * optargs;			// cmd opts
jmp_buf state;				// signalling state
//flow_handler_f flow_callback = &update_stats_print_flow;
flow_handler_f flow_callback = &update_stats;


int
main (int argc, const char * argv[])
{
	print_banner();
	if (geteuid()) {
        printf("ERROR: must be root ... exiting\n");
        abort();
    }
	optargs = parse_options(argc, argv);
#if DEBUG >= 1
	options_print(optargs);
#endif
	init_statistics();
	time_t start, stop;
	start = time(NULL);
	sniff(optargs);
	stop = time(NULL);
	cout << "processed in " << stop-start << " sec.\n";
	print_statistics();
	//print_details(); // this one is useless due to ageing
	flush_flows(flow_callback);
    return 0;
}

void
signal_handler (int sig)
{
	signal(sig,signal_handler);
	switch (sig) {
		case SIGINT:
			longjmp(state, SIGINT);
			break;
		default:
			break;
	}
}

void
print_banner (void)
{
	printf("%s\n%s\n%s\n",
		   APP_NAME,AUTHOR,EMAIL
	);
}

int
sniff (optarg_t *optargs)
{
	// some initial setup stuff
	pcap_t * handle;					// pcap session handle
	char *dev = optargs->dev;			// device to sniff on
	char errbuf[PCAP_ERRBUF_SIZE];		// error buffer
	struct bpf_program filter;			// compiled filter string
	bpf_u_int32 net, mask;				// network / netmask
	char snet[INET_ADDRSTRLEN], smask[INET_ADDRSTRLEN]; // string representations
	int dtl;							// data link type
	void (*callback) (u_char * args, const struct pcap_pkthdr *header, const u_char * packet);
	struct pcap_stat * stats = (struct pcap_stat *)malloc(sizeof(struct pcap_stat));
	

	// check interface
	if (dev == NULL) {
		printf("no interface specified, looking ...\n");
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "ERROR: couldn't find default device: %s\n", errbuf);
			fprintf(stderr, "try running as root / superuser\n");
			exit(EXIT_FAILURE);
		}
	}
	
	// find interface properties
	printf("check device properties ...\n");
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "WARNING: couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	inet_ntop(AF_INET, &(net), snet, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(mask), smask, INET_ADDRSTRLEN);
	printf("INFO: using device %s, %s / %s\n", dev, snet, smask);
	
	// open the session
	if (optargs->infile == NULL) {
		handle = pcap_open_live(dev, BUFSIZ, optargs->promiscuous, optargs->snaplen, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "ERROR: couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
		}		
	} else {
		handle = pcap_open_offline(optargs->infile, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "ERROR: couldn't open file %s: %s\n", optargs->infile, errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	// check datalink type
	// and set callback function appropriately
	// these are defined in handler.{h,cpp}
	dtl = pcap_datalink(handle);
	switch (dtl) {
		case DLT_EN10MB:
			callback = &ethernet_handler;
			break;
		case DLT_CHDLC:
			callback = &chdlc_handler;
			break;
		case DLT_RAW:
			callback = &ip_handler;
			break;
		default:
			fprintf(stderr, "ERROR: dtl %d unsupported.\n", dtl);
			exit(EXIT_FAILURE);
			break;
	}
	
	// compile filter
	if (pcap_compile(handle, &filter, optargs->filter, 0, net) == -1) {
		fprintf(stderr, "ERROR: couldn't parse filter %s: %s\n", optargs->filter, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	
	// set filter
	if (pcap_setfilter(handle, &filter) == -1) {
		fprintf(stderr, "ERROR: couldn't install filter %s: %s\n", optargs->filter, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	
	// do the loop, while not SIGINT
	signal(SIGINT,signal_handler);
	if (setjmp(state)==0) {
		pcap_loop(handle, -1, callback, NULL);
	} 
	
	// clean up
	printf("\n\n\n\n\nshutting down ...\n");
	if (pcap_stats(handle, stats)==-1) {
		printf("not captured anything\n");
	} else {
		printf("%d packets received\n%d packets dropped\n",stats->ps_recv,stats->ps_drop);
	}
	pcap_freecode(&filter);
	pcap_close(handle);
	return(0);
}
