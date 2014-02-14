/*
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
 *
 *  defines.h
 *  picflow
 *
 *  Created by Thomas Zink on 3/12/10.
 *
 */

#ifndef _DEFINES_H_
#define _DEFINES_H_

#define APP_NAME		"picDFI"
#define AUTHOR			"Thomas Zink"
#define EMAIL			"thomas.zink@uni-konstanz.de"

/*
 DEBUG
 levels:
 -1 : serialize flows to stdout / will be replaced
 0 : no debug
 1 : packet level
 2 : flow level
*/
#define DEBUG 0

/*
 assert table integrity
 i.e. after each insert, find the element
 assert it != table.end()
 */
#define ASSERT 0


#define AGE_SERVICE_TABLE 1

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS 0
#endif

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

#endif // _DEFINES_H_
