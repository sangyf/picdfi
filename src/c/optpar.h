/*
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
 *
 */
#ifndef _OPTPAR_H_
#define _OPTPAR_H_

#include <getopt.h>
#include <arpa/inet.h>

typedef struct optarg_s {
	char * dev;					// interface
	uint16_t snaplen;			// bytes to capture (-s)
	const char * infile;		// pcap input file name (-r)
	const char * outfile;		// flow serialization outfile (-o)
	const char * dumpfile;		// pcap dump file name (-w)
	uint8_t promiscuous;		// promiscuity	(-p)
	uint16_t to_ms;				// read timeout in ms (-m)
	const char * filter;		// remaining filter string
	long t_long;				// the long timeout for identification
	long t_short;				// the short timeout for identification
	long t_age;					// timeout for aging
} optarg_t;

optarg_t * parse_options (int argc, const char * argv[]);
void usage (void);
void options_print (optarg_t *p);
char *concat_argv(char **argv);

#endif
