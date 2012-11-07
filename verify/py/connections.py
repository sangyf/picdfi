#!/usr/bin/python
"""
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.

This script creates verification entries on a host running applications
that should be identifyed by executing and parsing the output of netstat.
Might not work equally well on different systems and diferrent netstat versions.
If looking for specific applcations add them to p2p_apps below.
"""

import subprocess
# import commands # only for unix
import struct
import socket
import cPickle
import sys
import os
from ftype import TYPE

__all__ = ['connentry']

class connentry (object):
    '''
    connection entry similar to an osdpi_flow entry.
    built from information retrieved by the
    command 'netstat'
    '''
    # add p2p processes here
    p2p_apps = ['bittorrent.exe','limewire.exe','emule.exe','amule.exe','utorrent.exe']
    
    def __init__ (self,sip='',sport=0,dip='',dport=0,protocol=None,app=None):
        ip0 = struct.unpack('!L',socket.inet_aton(sip))[0]
        ip1 = struct.unpack('!L',socket.inet_aton(dip))[0]
        port0 = int(sport)
        port1 = int(dport)
        if ip0 < ip1:
            self.lower_ip =ip0
            self.upper_ip =ip1
            self.lower_port = port0
            self.upper_port = port1
        else:
            self.lower_ip =ip1
            self.upper_ip =ip0
            self.lower_port = port1
            self.upper_port = port0
        if protocol == 'TCP':
            self.protocol = 6
        elif protocol == 'UDP':
            self.protocol = 17
        else:
            self.protocol = protocol
        self.detected_protocol = app
        if app != None:
            if app in self.p2p_apps:
                self.picdfi_type = TYPE['P2P']
            else:
                self.picdfi_type = TYPE['NONP2P']
        else:
            self.picdfi_type = TYPE['UNIDENTIFIED']

    def __repr__ (self):
        s = "%s %d %s %d %d %d %s" % \
            (socket.inet_ntoa(struct.pack('!L',self.lower_ip)),self.lower_port,\
            socket.inet_ntoa(struct.pack('!L',self.upper_ip)),self.upper_port,\
            self.protocol,self.picdfi_type,self.detected_protocol)
        return s

    def __hash__ (self):
        s = "%d%d%d%d%d" % (self.lower_ip,self.lower_port,self.upper_ip,self.upper_port,self.protocol)
        return hash(int(s))
        
def main (argv):
    foo,bar = run()
    if len(argv) > 0:
        bar.dump(argv[0])
    return foo,bar
    
def run():
    cmd = "netstat -anb 1"
    print 'Press Ctrl+C to stop netstat'
    foo = subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False)
    bar = stdouter()
    try:
        eval_stdout(foo,bar)
    except KeyboardInterrupt as e:
        print e
        os.system('taskkill /pid %s /F' % foo.pid)
    eval_stdout(foo,bar)   
    print 'done!'
    return foo,bar

class stdouter (dict):
    def __init__ (self,d={}):
        self.sip = ''
        self.dip = ''
        self.sport = 0
        self.dport = 0
        self.protocol = None
        self.app = None
        dict.__init__(self,d)
    def parse_line (self,line):
        if not line.isspace():
            t = line.lstrip().split()
            if t[0] == 'UDP' or t[0] == 'TCP':
                self.sip, self.sport = t[1].split(':')
                self.dip, self.dport = t[2].split(':')
                self.protocol = t[0]
            elif t[0].startswith('['):
                self.app = t[0][1:-1]
                if self.sip != '*' and self.dip != '*':
                    e = connentry(self.sip,self.sport,self.dip,self.dport,self.protocol,self.app)
                    self[hash(e)] = e
    def dump(self,fname):
        # unfortunately pickling and unpickling
        # seems to be problematic over os boundaries (win, unix, mac)
        #cPickle.dump(dict(self),fname)
        # so we just write every value to a text file
        f = open(fname,'w')
        for v in self.values():
            print >> f, v
        f.close()
    
def eval_stdout(foo,bar):
    for line in foo.stdout:
        bar.parse_line(line)
        print line
    
if __name__ == '__main__':
    foo,bar = main(sys.argv[1:])

