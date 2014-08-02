/*
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
 *
 */
#include "optpar.h"
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char * concat_argv(char **argv)
{
	char **p;
	u_short len = 0;
	char *buf;
	char *src, *dst;
	
	p = argv;
	if (*p == 0)
		return 0;
	
	while (*p)
		len += strlen(*p++) + 1;
	
	buf = (char *)malloc(len);
	if (buf == NULL) {
		fprintf(stdout, "ERROR: could not allocate memory for argv concatenation!\n");
		exit(EXIT_FAILURE);
	}
	
	p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0') ;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';
	
	return buf;
}


optarg_t * parse_options (int argc, const char * argv[])
{
	optarg_t *poptarg = (optarg_t *) malloc(sizeof(optarg_t));
	if (!poptarg) {
		fprintf(stderr, "ERROR: could not allocate memory for option parser!\n");
		exit(EXIT_FAILURE);
	}
	
	// set defaults
	poptarg->promiscuous = 1;
	poptarg->to_ms = 100;
	poptarg->snaplen = 100;
	poptarg->t_long = 10 * 60;
	poptarg->t_short = 10;
	poptarg->t_age = 30;
	
	// check arguments
	int c;
	while ((c = getopt(argc, (char**)argv, "s:r:o:w:m:i:A:S:L:p?h")) != -1) {
		switch (c) {
			case 's':
				poptarg->snaplen = atoi(optarg);
				break;
			case 'r':
				poptarg->infile = optarg;
				break;
			case 'o':
				poptarg->outfile = optarg;
				break;
			case 'w':
				poptarg->dumpfile = optarg;
				break;
			case 'm':
				poptarg->to_ms = atoi(optarg);
				break;
			case 'p':
				poptarg->promiscuous = 0;
				break;
			case 'i':
				poptarg->dev = optarg;
				break;
			case 'S':
				poptarg->t_short = atoi(optarg);
				break;
			case 'L':
				poptarg->t_long = atoi(optarg);
				break;				
			case 'A':
				poptarg->t_age = atoi(optarg);
				break;
			case '?':
				usage();
				break;
			case 'h':
				usage();
				break;
			default:
				usage();
				break;
		}
	}
	
	// set the remaining as filter string
	poptarg->filter = concat_argv((char**)&argv[optind]);
	return(poptarg);
}

void usage (void)
{
	printf(
		   "usage: ipflow [options]\n"
		   "options:\n"
		   "-i\t\tinterface, device\n"
		   "-r\t\tpcap input file\n"
		   "-w\t\tpcap dump file (not yet implemented!)\n"
		   "-o\t\tflow serialization file (not yet implemented!)\n"
		   "-p\t\tdon't put interface into promiscuous mode\n"
		   "-s\t\tsnaplen, how many bytes to capture for each packet\n"
		   "-m\t\ttimeout in ms\n"
		   "-A\t\tageing timeout in sec\n"
		   "-S\t\t'uncertain' timeout in sec\n"
		   "-L\t\t'certain' timeout in sec\n"
	);
	exit(EXIT_SUCCESS);
}

void options_print (optarg_t *p)
{
	printf(
		   "Options\n"
		   "address: %p\n"
		   "dev: %s\n"
		   "snaplen: %i\n"
		   "infile: %s\n"
		   "outfile: %s\n"
		   "dumpfile: %s\n"
		   "promiscuous: %i\n"
		   "to_ms: %i\n"
		   "filter: %s\n"
		   ,p,p->dev,p->snaplen,
		   p->infile,p->outfile,p->dumpfile,
		   p->promiscuous,p->to_ms,p->filter
	);
}
