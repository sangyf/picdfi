#!/usr/bin/python
"""
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.

create_netstat_file.py

creates a netstat like verification output from
pcap capture files by just taking all connection
to/fro specific ports. Requires, that the portnumber
of p2p applications are known. designed for post mortem
generation of netstat verification files. if possible
run connections.py during captures. output is written to
stdout. if a file should be generated use >>.
"""

import dpkt
import pcap
import socket
import sys
import struct
from ftype import TYPE

Ethernet = dpkt.ethernet.Ethernet

class entry (object):
    def __init__ (self,eth):
        ip0 = struct.unpack('!L',eth.data.src)[0]
        ip1 = struct.unpack('!L',eth.data.dst)[0]
        port0 = int(eth.data.data.sport)
        port1 = int(eth.data.data.dport)
        if ip0 < ip1:
            self.lower_ip = ip0
            self.upper_ip = ip1
            self.lower_port = port0
            self.upper_port = port1
        else:
            self.lower_ip = ip1
            self.upper_ip = ip0
            self.lower_port = port1
            self.upper_port = port0
        self.protocol = eth.data.p
        self.detected_protocol = 'undetected'
        self.picdfi_type = TYPE['P2P']
    def __hash__ (self):
        s = "%d%d%d%d%d" % (self.lower_ip,self.lower_port,self.upper_ip,self.upper_port,self.protocol)
        return hash(int(s))
    def __repr__ (self):
        s = "%s %d %s %d %d %d %s" % \
            (socket.inet_ntoa(struct.pack('!L',self.lower_ip)),self.lower_port,\
            socket.inet_ntoa(struct.pack('!L',self.upper_ip)),self.upper_port,\
            self.protocol,self.picdfi_type,self.detected_protocol)
        return s
            
class pcaphandler (dict):
    def __init__ (self,d={}):
        dict.__init__(self,d)
        
    def __call__ (self,pktlen,buf,ts):
        eth = Ethernet(buf)
        item = entry(eth)
        self[hash(item)] = item

    def __repr__ (self):
        return "%s(%s)" % (self.__class__.__name__,dict.__repr__(self))

    def __str__ (self):
        return '\n'.join([x.lstrip(' ') for x in str(self.values())[1:-1].split(',')])    

def main (argv):
    if len(argv) < 3:
        print "Illegal number of arguments. use: %s <pcap file> <filter_str>" % argv[0]
        exit(0)
    print >> sys.stderr, 'using file: %s' % argv[1]
    #fstr = s = "port " + " or port ".join(argv[2:])
    fstr = ' '.join(argv[2:])
    print >> sys.stderr, "using filter string: %s" % fstr
    p = pcap.pcapObject()
    p.open_offline(argv[1])
    p.setfilter(fstr,0,0)
    phandler = pcaphandler()
    p.loop(0,phandler)
    print phandler
    return phandler
    

if __name__ == '__main__':
    phandler = main(sys.argv)
