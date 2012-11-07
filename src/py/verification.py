#!/usr/bin/python -i
"""
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.

Verification module for picDFI

Reads in an OpenDPI result file (or any other file that meets file specs)
and builds a verification dictionary.

Verification File
-----------------
The verification file is ascii encoded and records some fields of osdpi flows.

typedef struct osdpi_flow {
	struct ipoque_flow_struct *ipoque_flow;
	u32 lower_ip;
	u32 upper_ip;
	u16 lower_port;
	u16 upper_port;
	u16 protocol;
	u16 picdfi_type;
	u32 detected_protocol;
} osdpi_flow_t;

{lower_ip,upper_ip,lower_port,upper_port,protocol,picdfi_type}
are evaluated, other values are ignored.
The ASCII values represent the byte values in hex.


Verification Dictionary
-----------------------
The dictionary is built using the same hash function as the bi-directional flow id extractor.
Keys are mapped to the picdfi flow type.

"""

__all__ = ['picverification','flowhandler','flowserializer','flowdestroyer','flowmemorizer','flowverifier']

import sys
import cPickle
import pcap
import struct
import socket
from patterns import *
from ftype import TYPE

class picverification (dict):

    class entry:
        def __init__ (self,buf,typ):
            if typ == 'osdpi':
                self._parse_osdpi_ (buf)
            elif typ == 'netstat':
                self._parse_netstat_ (buf)
            else:
                raise NotImplementedError()

        def _parse_osdpi_ (self,buf):
            splitted = buf[:-1].split() # remove last \n
            # original as in file
            lower_ip = int(splitted[0],16)
            upper_ip = int(splitted[1],16)
            lower_port = int(splitted[2],16)
            upper_port = int(splitted[3],16)
            # need to recompare, to compensate endianess and stuff
            # don't really know why, but doesn't work else
            if lower_ip < upper_ip:
                self.lower_ip = lower_ip
                self.upper_ip = upper_ip
                self.lower_port = lower_port
                self.upper_port = upper_port
            else:
                self.lower_ip = upper_ip
                self.upper_ip = lower_ip
                self.lower_port = upper_port
                self.upper_port = lower_port            
            self.protocol = int(splitted[4],16)
            self.picdfi_type = int(splitted[5],16)
            self.detected_protocol = int(splitted[6],16)

        def _parse_netstat_ (self,buf):
            print "buf: %s" % buf
            splitted = buf[:-1].split()
            self.lower_ip = struct.unpack('!L',socket.inet_aton(splitted[0]))[0]
            self.lower_port = int(splitted[1])
            self.upper_ip = struct.unpack('!L',socket.inet_aton(splitted[2]))[0]
            self.upper_port = int(splitted[3])
            self.protocol = int(splitted[4])
            self.picdfi_type = int(splitted[5])
            self.detected_protocol = splitted[6]

        def __repr__ (self):
            s = "%s %d %s %d %d %d %d" % \
                (socket.inet_ntoa(struct.pack('!L',self.lower_ip)),self.lower_port,\
                 socket.inet_ntoa(struct.pack('!L',self.upper_ip)),self.upper_port,\
                 self.protocol,self.picdfi_type,self.detected_protocol)
            return s
        
        def __hash__ (self):
            s = "%d%d%d%d%d" % (self.lower_ip,self.lower_port,self.upper_ip,self.upper_port,self.protocol)
            return hash(int(s))
            
            
        
    def __init__ (self, vfile = None, nfile = None, d = {}):
        # nfile is a netstat capture file
        # first source for viable verification
        if nfile != None:
            self.nfile = open(nfile,'r')
            self.buildtable(self.nfile,'netstat')
            self.nfile.close()
        # vfile is a osdpi verification file
        if vfile != None:
            self.vfile = open(vfile,'r')
            self.buildtable(self.vfile,'osdpi')
            self.vfile.close()
        self._initsummary_ ()
        dict.__init__(self,d)

    def buildtable (self, fhandle, typ):
        for line in fhandle:
            entry = self.entry(line,typ)
            h = hash(entry)
            if self.has_key(h):
                print >> sys.stderr, "WARNING: Verification entry already present %s" % entry
            else:
                self[h] = entry

    def _initsummary_ (self):
        """initialize the summary counter structure

        keeps counters [nflows, nbytes, npackets] for
        sum (sum of all)
        unverified p2p (reported p2p, unable to verify)
        unverified non p2p (reported nonp2p, unable to verify)
        p2p, true positive (verified as p2p)
        p2p, false positive (reported p2p, but verified as nonp2p)
        nonp2p, true negative (verified as nonp2p) 
        nonp2p, false negative (reported as nonp2p, verified as p2p)
        """
        self.dsum = {}
        self.dsum['sum'] = [0,0,0]
        self.dsum['up'] = [0,0,0]
        self.dsum['un'] = [0,0,0]
        self.dsum['tp'] = [0,0,0]
        self.dsum['fp'] = [0,0,0]
        self.dsum['tn'] = [0,0,0]
        self.dsum['fn'] = [0,0,0]
        self.dsum['no'] = [0,0,0]
        
    def verify (self, f):
        #struct.unpack('!L',socket.inet_aton(ip))[0]
        sip = struct.unpack('!L',f.sip)[0]
        dip = struct.unpack('!L',f.dip)[0]
        if sip < dip:
                s = "%d%d%d%d%d" % (sip,f.sport,dip,f.dport,f.protocol)
        else:
                s = "%d%d%d%d%d" % (dip,f.dport,sip,f.sport,f.protocol)
        fid = hash(int(s))
        nflows = 1
        nbytes = f.nbytes
        npackets = f.npackets
        l = None
        try:
            entry = self[fid]
            ftype = entry.picdfi_type
            if ftype == TYPE['UNIDENTIFIED']:
                # unable to verify
                if f.ftype == TYPE['P2P']:
                    l = self.dsum['up']
                    #print >> sys.stderr, "Unverified P2P: %s" % entry
                elif f.ftype == TYPE['NONP2P'] or f.ftype == TYPE['POSSIBLE'] or f.ftype == TYPE['UNIDENTIFIED']:
                    l = self.dsum['un']
                    #print >> sys.stderr, "Unverified NONP2P: %s" % entry
            elif ftype == TYPE['P2P']:
                if f.ftype == TYPE['P2P']:
                    l = self.dsum['tp']
                    #print >> sys.stderr, "True Positive: %s" % entry
                elif f.ftype == TYPE['NONP2P'] or f.ftype == TYPE['POSSIBLE'] or f.ftype == TYPE['UNIDENTIFIED']:
                    l = self.dsum['fn']
                    #print >> sys.stderr, "False Negative: %s" % entry
            elif ftype == TYPE['NONP2P']:
                if f.ftype == TYPE['P2P']:
                    l = self.dsum['fp']
                    #print >> sys.stderr, "False Positive: %s" % entry
                elif f.ftype == TYPE['NONP2P'] or f.ftype == TYPE['POSSIBLE'] or f.ftype == TYPE['UNIDENTIFIED']:
                    l = self.dsum['tn']
                    #print >> sys.stderr, "True Negative: %s" % entry
            else:
                print >> sys.stderr, "Unknown type: %s, %s, %s" % (entry, ftype, TYPE[ftype])
        except KeyError as ke:
            print ke, s
            print "%s %d %s %d %d" % (pcap.ntoa(sip),f.sport,pcap.ntoa(dip),f.dport,f.protocol)
            l = self.dsum['no']
        # here update verification results
        try:
            l[0] += 1
            l[1] += nbytes
            l[2] += npackets
        except TypeError as e:
            print >> sys.stderr, "%s" % e
            print >> sys.stderr, s, entry
            print >> sys.stderr, ftype, TYPE[ftype], f.ftype, TYPE[f.ftype]
            exit(1)
        s = self.dsum['sum']
        s[0] += 1
        s[1] += nbytes
        s[2] += npackets

    def verifyfile (self,fname):    
        """verifyfile (fname) -- iterates over flows in file fname and verifies these
        the file to verify holds flow entries, serialized by the flowtable
        using the python pickle serialization.
        """
        fhandle = open(fname,'r')
        while True:
            try:
                flo = cPickle.load(fhandle)
                self.verify(flo)
            except EOFError:
                break

    def summary (self):
        s = 'VERIFICATION SUMMARY\n'
        total = self.dsum['sum']
        s += "nflows: %d\t\tnbytes: %d\t\tnpacket: %d\n" % (total[0],total[1],total[2])
        s += "type\t\t\t%c flows\t\t%c bytes\t\t%c packets\n" % ('%','%','%')
        t = self.dsum['up']
        up = [t[i]/float(total[i])*100 for i in range(0,len(t))]
        s += "Unverified (P2P):\t%.3f\t\t%.3f\t\t%.3f\n" % (up[0],up[1],up[2])
        t = self.dsum['un']
        un = [t[i]/float(total[i])*100 for i in range(0,len(t))]
        s += "Unverified (NONP2P):\t%.3f\t\t%.3f\t\t%.3f\n" % (un[0],un[1],un[2])
        t = self.dsum['tp']
        tp = [t[i]/float(total[i])*100 for i in range(0,len(t))]
        s += "True Positives:\t\t%.3f\t\t%.3f\t\t%.3f\n" % (tp[0],tp[1],tp[2])
        t = self.dsum['fp']
        fp = [t[i]/float(total[i])*100 for i in range(0,len(t))]
        s += "False Positives:\t%.3f\t\t%.3f\t\t%.3f\n" % (fp[0],fp[1],fp[2])
        t = self.dsum['tn']
        tn = [t[i]/float(total[i])*100 for i in range(0,len(t))]
        s += "True Negatives:\t\t%.3f\t\t%.3f\t\t%.3f\n" % (tn[0],tn[1],tn[2])
        t = self.dsum['fn']
        fn = [t[i]/float(total[i])*100 for i in range(0,len(t))]
        s += "False Negatives:\t%.3f\t\t%.3f\t\t%.3f\n" % (fn[0],fn[1],fn[2])
        t = self.dsum['no']
        no = [t[i]/float(total[i])*100 for i in range(0,len(t))]
        s += "No Entry:\t\t%.3f\t\t%.3f\t\t%.3f\n" % (no[0],no[1],no[2])
        s += "true positive: identified P2P, verified P2P\n"
        s += "false positive: identified P2P, verified NONP2P\n"
        s += "true negative: identified NONP2P, verified NONP2P\n"
        s += "false negative: identified NONP2P, verified P2P"
        return s
        
        
            
class flowhandler (abstractbaseclass):
    """serializer, serializes picflows to harddisk"""
    def __init__ (self,*args,**kwargs): pass
    def __call__ (self,f): abstract()

class flowserializer (flowhandler):
    def __init__ (self, *args, **kwargs):
        self.file = open(kwargs['fname'],'w')
    def __call__ (self,f):
        s = "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (socket.inet_ntoa(f.sip),f.sport,socket.inet_ntoa(f.dip),f.dport,f.protocol,f.created,f.lastaccess,f.npackets,f.nbytes,f.ftype)
        print >> self.file, s
        del f

class flowpickler (flowhandler):
    def __init__ (self, *args, **kwargs):
        self.file = open(kwargs['fname'],'w')
    def __call__ (self,f):
        cPickle.dump(f, self.file)
        del f

class flowdestroyer (flowhandler):
    def __init__ (self,*args,**kwargs): pass
    def __call__ (self,f): del f

class flowmemorizer (list,flowhandler):
    def __init__ (self,l=[]):
        list.__init__ (self,l)
    def __call__ (self,f):
        self.append(f)

class flowverifier (flowhandler):
    def __init__ (self, verify):
        self.verify = verify
    def __call__ (self,f):
        self.verify.verify(f)
        del f
        

if __name__ == '__main__':
    vfile = sys.argv[1]
    fname = None
    if len(sys.argv) > 2:
        fname = sys.argv[2]
    v = picverification(vfile)
    if fname != None:
        v.verifyfile(fname)
        
