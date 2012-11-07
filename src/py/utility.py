"""
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
"""
__all__ = ['packethandler','ptos','tstolocaltime','decodeippacket']

# +-------------------------------------------------------------+
# |-IMPORTS-----------------------------------------------------|
# +-------------------------------------------------------------+
import pcap, dpkt, socket
import struct
import time
from ftype import TYPE
from dpkt.chdlc import Chdlc
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.ethernet import ETH_TYPE_IP

# +-------------------------------------------------------------+
# |-CLASSES-----------------------------------------------------|
# +-------------------------------------------------------------+
hexdump = dpkt.hexdump

class packethandler (object):
    ncalls = 0
    def __new__ (cls,*args,**kw):
        o = object.__new__(cls)
        # - define methods to use in newclass -
        # decoder
        dlt = kw['DLT']
        def _decode_chdlc_ (buf):
            frame = Chdlc(buf)
            if frame.type == ETH_TYPE_IP:
                return frame.data
            else:
                return None
        def _decode_ethernet_ (buf):
            frame = Ethernet(buf)
            if frame.type == ETH_TYPE_IP:
                return frame.data
            else:
                return None
        if dlt == pcap.DLT_C_HDLC:
            setattr(o,'decode',_decode_chdlc_)
        elif dlt == pcap.DLT_EN10MB:
            setattr(o,'decode',_decode_ethernet_)
        elif dlt == pcap.DLT_RAW:
            setattr(o,'decode', IP)
        # verbose
        def v0 (self,*args):
            pass
        def v1 (self,eth,ts):
            print "received: %d" % self.ncalls
        def v2 (self,eth,ts):
            print ptos(eth,ts)
        def v3 (self,eth,ts):
            print ptos(eth,ts)
            print hexdump(str(eth)) + '\n'
        v = [v0,v1,v2,v3]
        setattr(o,'_verbose_',v[kw['opts'].v])
        # __call__
        def call_std (self,pktlen,buf,ts):
            frame = self.decode(buf)
            if frame:
                pkt = (pktlen,frame,ts)
                fid = self.ftab.put(pkt)
                if fid != None:
                    flo = self.ftab[fid]
                    if flo.ftype == TYPE['UNIDENTIFIED'] or flo.ftype == TYPE['POSSIBLE']:
                        self.ident.identify(flo)
            self._verbose_(self,frame,ts)
        def call_with_ofile (self,pktlen,buf,ts):
            frame = self.decode(buf)
            if frame:
                pkt = (pktlen,frame,ts)
                fid = self.ftab.put(pkt)
                if fid != None:
                    flo = self.ftab[fid]
                    if flo.ftype == TYPE['UNIDENTIFIED'] or flo.ftype == TYPE['POSSIBLE']:
                        self.ident.identify(flo)
            self._verbose_ (self,frame,ts)
            self.writer.writepkt(buf,ts)
        _call_ = None
        if kw['opts'].ofile != '':
            setattr(o,'writer',dpkt.pcap.Writer(open(kw['opts'].ofile,'w'),kw['opts'].snaplen))
            _call_ = call_with_ofile
        else:
            _call_ = call_std
        setattr(o,'_handle_',_call_)
        return o
            
    def __init__ (self,*args,**kw):
        for k,v in kw.items(): setattr(self,k,v)
    
    def __str__ (self):
        return str(self.__dict__)
    
    def __repr__ (self):
        return "%s(%s)" % (self.__class__.__name__,self.__dict__)
    
    def __call__ (self,pktlen,buf,ts):
        self.ncalls += 1
        return self._handle_(self,pktlen,buf,ts)        
# +-------------------------------------------------------------+
# |-FUNCTIONS---------------------------------------------------|
# +-------------------------------------------------------------+
def ptos (buf,ts):
    """ptos (buf,ts) -> str
    
    convert a packet to a nice string.
    inspired by print_packet of pcap sniff.py example
    """
    s = '%14s' % tstolocaltime(ts)
    if buf.type == dpkt.ethernet.ETH_TYPE_IP:
        s += ', %15s >> %15s, len: %4d, protocol: %3d' % (\
            pcap.ntoa(struct.unpack('i',buf.ip.src)[0]),\
            pcap.ntoa(struct.unpack('i',buf.ip.dst)[0]),\
            buf.ip.len, buf.ip.p
        )
        # check if udp or tcp
        if buf.ip.p == 17 or buf.ip.p == 6:
            s += ', sport: %6d, dport: %6d' % (\
                buf.ip.data.sport,buf.ip.data.dport)
    return s
# +-------------------------------------------------------------+
def decodeippacket (ippkt):
        s = ['Received: %s, %s' % (tstolocaltime(ippkt[2]),ippkt[2]),'Frame']
        dct = ippkt[1].__dict__
        for k,v in dct.items():
            if k != 'data' and k != 'ip':
                if k == 'src' or k == 'dst':
                    v = ':'.join(['%02X' % ord(i) for i in v])
                s.append('%s: %s' % (k,str(v)))
        dct = dct['data'].__dict__
        s.append('Datagram')
        for k,v in dct.items():
            if k != 'data' and k != 'tcp' and k != 'udp':
                if k == 'src' or k == 'dst':
                    v = '.'.join([str(ord(x)) for x in v])
                s.append('%s: %s' % (k,v))
        dct = dct['data'].__dict__
        s.append('Segment')
        for k,v in dct.items():
            if k != 'data':
                if k == 'opts':
                    v = ''.join(['%02x' % ord(i) for i in v])
                s.append('%s: %s' % (k,v))
        dct = dct['data']
        s.append('Message')
        s.append(' '.join(['%02x' % ord(i) for i in dct]))
        return '\n'.join(s)
# +-------------------------------------------------------------+
def tstolocaltime (ts):
    s = '%s:%.4f' % (\
        time.strftime('%H:%M',time.localtime(ts)),\
        ts % 60)
    return s
# +-------------------------------------------------------------+
# EOF
