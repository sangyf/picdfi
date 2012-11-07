/*
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
 *
 *  fileio.cpp
 *  picflow
 *
 *  Created by Thomas Zink on 3/24/10.
 *
 */

#include "fileio.h"
#include "flow.h"
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h> // in_addr
#include <arpa/inet.h> // inet_ntop
#include <math.h> // pow, modf
#include <string.h> // memset
#include <map>
#include <assert.h>

extern verification_table_t verify;


/*
 load_verification_file
 loads and parses the verification file.
 it has csv format and must have the following fileds without header:
 
 lower_ip,lower_port,upper_ip,upper_port,protocol,created ts,touched ts,npackets,nbytes,flowtype\n
 
 a sample entry looks like this
 
 134.34.10.38,57763,134.34.3.2,53,17,1244542904.09,1244542904.44,3,280,1
 
 each line is parsed and transformed to a pic flow and added to the verification table.
 we could use binary encoding which would make parsing faster, but also more problematic
 because of os and arch boundaries. also, it's easier to read this way :).
*/
void
load_verification_file (const char * fname)
{
	static u_int32_t collisions = 0;
	FILE * fp = fopen(fname, "r");
	if (fp == NULL) {
		fprintf(stderr, "ERROR: could not open file %s!\n", fname);
		exit(EXIT_FAILURE);
	}
	
	// copy file characters
	char buf[100];
	memset(buf, 0, 100);
	char *p = buf;
	
	// flow information
	struct in_addr la,ua;
	u_short lp,up;
	u_char ip_p;
	struct timeval created,touched;
	u_int32_t npackets,nbytes;
	enum picdfi_type ftype;
	
	// parse the file
	// read and evaluate every character
	// we could copy and evaluate each line but need to check every char anyway
	int c, field = 0;	// for fgetc, number field
	do {
		c = fgetc(fp);
		// on \n we got all flow info
		if (c == '\n') {
			*p = '\0';
			ftype = (picdfi_type) atoi((const char *)buf);
			
			// set connection
			pic_connection_t conn;
			// check lower < upper
			if (la.s_addr <= ua.s_addr) {
				conn.lower = new pic_service_t (la, lp);
				conn.upper = new pic_service_t (ua, up);
			} else {
				conn.lower = new pic_service_t (ua, up);
				conn.upper = new pic_service_t (la, lp);
			}
			conn.ip_p = ip_p;
			
			// set flow info
			pic_flow_t flow;
			flow.npackets = npackets;
			flow.nbytes = nbytes;
			flow.created = created;
			flow.touched = touched;
			flow.flow_type = ftype;
			
			// add to verification table
			pair<verification_table_t::iterator,bool> ret;
			ret = verify.insert(verification_table_entry_t (conn,flow));
#if ASSERT == 1
			// now search for it
			verification_table_t::iterator it;
			it = verify.find(conn);
			assert(it != verify.end());
#endif
			if (ret.second == false) {
				++collisions;
#if DEBUG >= 2
				cout << "(verify collision) " << ret.first->first << " : " << ret.first->second << endl;
			} else {
				cout << "(verify insert) " << ret.first->first << " : " << ret.first->second << endl;
#endif
			}

			// be verbose
#if DEBUG < 1
			printf("\rflows added: \x1b[33m%-8d\x1b[0m\tcollisions: \x1b[33m%-8d\x1b[0m"
				   ,(int)verify.size(),collisions);
#endif
			// clean up
			field = 0;
			memset(buf, 0, 100);
			p = buf;
		} else if (c == ',') {
			*p = '\0';
			double tmp,sec,usec;
			switch (field) {
				case 0:
					la.s_addr = inet_addr((const char *)buf);
					break;
				case 1:
					lp = htons(atoi((const char *)buf));
					break;
				case 2:
					ua.s_addr = inet_addr((const char *)buf);
					break;
				case 3:
					up = htons(atoi((const char *)buf));
					break;
				case 4:
					ip_p = atoi((const char *)buf);
					break;
				case 5:
					tmp = atof((const char*)buf);
					usec = modf(tmp,&sec);
					created.tv_sec = (long)sec;
					created.tv_usec = (int)(usec*pow(10,6));
					break;
				case 6:
					tmp = atof((const char*)buf);
					usec = modf(tmp,&sec);
					touched.tv_sec = (long)sec;
					touched.tv_usec = (int)(usec*pow(10,6));
					break;
				case 7:
					npackets = atoi((const char *)buf);
					break;
				case 8:
					nbytes = atoi((const char *)buf);
					break;
				default:
					break;
			}
			field++;
			memset(buf, 0, 100);
			p = buf;
		} else {
			*(p++) = c;
			//++p;
		}
	} while (c!=EOF);

	fclose(fp);
	printf("\n");
}