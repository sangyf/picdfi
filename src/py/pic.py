"""
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.

PIC DFI implementation

implements flow, flowtable and flow identification as simulation
of a PIC (physical interface card) hardware.

author: thomaszink
contributors: samxia, zhanchong
"""

__all__ = ['TYPE','picflow','picflowtable','picidentifier']

# +-------------------------------------------------------------+
# IMPORTS
# +-------------------------------------------------------------+
import sys
import socket
from verification import *
from dpkt.ethernet import Ethernet, ETH_TYPE_IP
from dpkt.ip import IP_PROTO_TCP, IP_PROTO_UDP
from operator import *
from idextraction import *
from ftype import TYPE

# +-------------------------------------------------------------+
# CLASSES
# +-------------------------------------------------------------+

# +-------------------------------------------------------------+
class picflow (object):
    def __init__ (self,ippkt):
        self.sip = ippkt[1].src
        self.sport = ippkt[1].data.sport
        self.dip = ippkt[1].dst
        self.dport = ippkt[1].data.dport
        self.protocol = ippkt[1].p
        self.created = ippkt[2]
        self.lastaccess = ippkt[2]
        self.npackets = 1
        self.nbytes = ippkt[1].len
        self.opts = 0x00
        self.payload = ippkt[1].data.data[:4]
        self.ftype = TYPE['UNIDENTIFIED']
        # counters to count bytes and packets after p2p identification
        # only in software simulation
        self.first_ident_pktseq = 0
        self.ident_pkts = 0
        self.ident_bytes = 0
        
    def update (self,ippkt):
        self.npackets += 1
        self.nbytes += ippkt[0]
        self.lastaccess = ippkt[2]
        self.payload = ippkt[1].data.data[:4]
        if self.ftype == TYPE['P2P']:
            self.ident_pkts += 1
            self.ident_bytes += ippkt[1].len
            
    def _getduration_ (self):
        return self.lastaccess - self.created
    duration = property(fget=_getduration_)
    
    def _getips_ (self):
        return [socket.inet_ntoa(self.sip),socket.inet_ntoa(self.dip)]
    ips = property(fget=_getips_)

    def _getports_ (self):
        return [self.sport,self.dport]
    ports = property(fget=_getports_)

    def __str__ (self):
        s = "%.4f-%.4f, %s:%s >> %s:%s, protocol: %d, npackets: %d, nbytes: %d, type: %d"\
            % (self.created,self.lastaccess,\
               socket.inet_ntoa(self.sip),self.sport,\
               socket.inet_ntoa(self.dip),self.dport,\
               self.protocol,self.npackets,self.nbytes,self.ftype)
        return s

    def __repr__ (self):
        s = "%s(%s)" % (self.__class__.__name__,self.__dict__)
        return s
            
    def packetfreq (self):
        duration = self.duration
        return self.npackets/duration if duration > 0 else self.npackets
    
    def bytefreq (self):
        duration = self.duration
        return self.nbytes/duration if duration > 0 else self.nbytes

    def bandwidth (self,unit=8./1000.,rate=1.):
        nbytes = self.nbytes * unit
        time = self.duration * rate
        return (nbytes) / (time) if time > 0 else nbytes

    def bytes_per_packet (self):
        return self.nbytes/float(self.npackets)

    def time_per_packet (self):
        return self.duration / float(self.npackets)
# +-picflow-----------------------------------------------------+

# +-------------------------------------------------------------+
class flowserializer (object):
    def __init__ (self):
        pass
# +-flowserializer----------------------------------------------+

# +-------------------------------------------------------------+
class picflowlist (list):
    def __init__ (self,l=[]):
        list.__init__ (self,l)

    def _getips_ (self):
        return list(set(reduce(add,[f.ips for f in self]))) if len(self) > 0 else []
    ips = property(fget=_getips_)

    def _getports_ (self):
        return list(set(reduce(add,[f.ports for f in self]))) if len(self) > 0 else []
    ports = property(fget=_getports_)

    def _getprotocols_ (self):
        return list(set([f.protocol for f in self])) if len(self) > 0 else []
    protocols = property(fget=_getprotocols_)

    def _getcreated_ (self):
        return min([f.created for f in self]) if len(self) > 0 else 0.0
    created = property(fget=_getcreated_)

    def _getlastaccess_ (self):
        return max([f.lastaccess for f in self]) if len(self) > 0 else 0.0
    lastaccess = property(fget=_getlastaccess_)

    def _getnpackets_ (self):
        return sum([f.npackets for f in self]) if len(self) > 0 else 0
    npackets = property(fget=_getnpackets_)

    def _getnbytes_ (self):
        return sum([f.nbytes for f in self]) if len(self) > 0 else 0
    nbytes = property(fget=_getnbytes_)

    def _getduration_ (self):
        return self.lastaccess - self.created
    duration = property(fget=_getduration_)

    def _getftype_ (self):
        return list(set([f.ftype for f in self])) if len(self) > 0 else []
    ftype = property(fget=_getftype_)

    def bytes_per_packet (self):
        return self.nbytes/float(self.npackets)

    def time_per_packet (self):
        return self.duration / float(self.npackets)

    def histogram (self):
        """histogram() -> { ftype: [freq,nbytes,npackets] }"""
        dct = {}
        for f in self:
            if dct.has_key(f.ftype):
                value = dct[f.ftype]
                value[0] += 1
                value[1] += f.nbytes
                value[2] += f.npackets
            else:
                dct[f.ftype] = [1,f.nbytes,f.npackets]
        return dct
# +-picflowlist-------------------------------------------------+

# +-------------------------------------------------------------+
class picflowtable (dict):
    def __init__ (self,d={},idx=bi5tuple(),A=30,handler=flowdestroyer()):
        self.extractid = idx
        self._A_ = A
        self.created = 0.0
        self.ts = 0.0
        self.handler = handler
        self._initsummary_()  
        dict.__init__(self,d)

    def __str__ (self):
        s = ''
        for fid,flo in self.items():
            s += '%s: %s\n' % (fid,flo)
        return s[:-1] # without last \n

    def __repr__ (self):
        s = "%s(%s,**%s)" % (self.__class__.__name__,dict.__repr__(self),self.__dict__)
        return s

    def __hash__ (self):
        return id(self)

    def _initsummary_ (self):
        # the result summary { ftype: [nflows, nbytes, npackets] }
        self.dsum = {}
        self.dsum['nflows'] = 0
        self.dsum['npackets'] = 0
        self.dsum['nbytes'] = 0
        self.dsum['ident_pkts'] = 0
        self.dsum['ident_bytes'] = 0
        for typ in TYPE.keys():
            if isinstance(typ,int):
                self.dsum[typ] = [0,0,0]
                  
    def _updatesummary_ (self,f):
        nflows = 1
        nbytes = f.nbytes
        npackets = f.npackets
        try:
            values = self.dsum[f.ftype]
            values[0] += nflows
            values[1] += nbytes
            values[2] += npackets
        except KeyError:
            self.dsum[f.ftype] = [nflows,nbytes,npackets]
        if self.created == 0.0:
            self.created = f.created
        self.dsum['nflows'] += nflows
        self.dsum['nbytes'] += nbytes
        self.dsum['npackets'] += npackets
        if f.ftype == TYPE['P2P']:
            self.dsum['ident_pkts'] += f.ident_pkts
            self.dsum['ident_bytes'] += f.ident_bytes
        
    def _getnpackets_ (self):
        return self.dsum['npackets']
    npackets = property(fget=_getnpackets_)

    def _getnbytes_ (self):
        return self.dsum['nbytes']
    nbytes = property(fget=_getnbytes_)

    def _getnflows_ (self):
        return self.dsum['nflows']
    nflows = property(fget=_getnflows_)

    def _getidentpkts_(self):
        return self.dsum['ident_pkts']
    ident_pkts = property(fget=_getidentpkts_)

    def _getidentbytes_(self):
        return self.dsum['ident_bytes']
    ident_bytes = property(fget = _getidentbytes_)

    def _getduration_ (self):
        return self.lastaccess - self.created
    duration = property(fget=_getduration_)

    def bytes_per_packet (self):
        nbytes = float(self.nbytes)
        npackets = float(self.npackets)
        return nbytes/npackets if npackets > 0 else 0

    def time_per_packet (self):
        duration = float(self.duration)
        npackets = float(self.npackets)
        return duration/npackets if npackets > 0 else 0
    
    def put (self,pkt):
        ts = pkt[2]
        fid = self.extractid(pkt)
        if fid == None:
            return None
        try:
            self[fid].update(pkt)
        except KeyError:
            self[fid] = picflow(pkt)
        if (ts-self.ts) > self._A_:
            self.age(ts)
            self.ts = ts
        self.lastaccess = ts
        return fid
    
    def age (self,ts):
        for fid,flo in self.items():
            if (ts-flo.lastaccess) > self._A_:
                f = self.pop(fid)
                self._updatesummary_ (f)
                self.handler(f)

    def flush (self):
        for fid in self.keys():
            f = self.pop(fid)
            self._updatesummary_(f)
            self.handler(f)

    def summary (self):
        self.flush()
        s = "FLOW TABLE SUMMARY\n"
        s += "created: %s\t\tlastaccess: %s\t\tduration: %s\n" % \
            (self.created,self.lastaccess,self.duration)
        s += "nflows: %s\t\tnbytes: %s\t\tnpackets: %s\n" % \
             (self.nflows, self.nbytes, self.npackets)
        fident_bytes = self.ident_bytes/float(self.nbytes)*100
        fident_pkts = self.ident_pkts/float(self.npackets)*100
        s+= "\t\t%c ident_bytes: %s\t\t%c ident_packtes: %s\n" % ('%',fident_bytes, '%', fident_pkts)
        s += "type\t\t\tnflows\t\t%c flows\t\t%c bytes\t\t%c packets\n" % ('%','%','%')
        for typ in TYPE.keys():
            if isinstance(typ,int):
                t = TYPE[typ]
                v = self.dsum[typ]
                fflows = v[0] / float(self.nflows) * 100
                fbytes = v[1] / float(self.nbytes) * 100
                fpackets = v[2] / float(self.npackets) * 100
                s += "%13s:\t\t%s\t\t%.3f\t\t%.3f\t\t%.3f\n" % \
                    (t,v[0],fflows,fbytes,fpackets)
        return s[:-1]
# +-flowtable---------------------------------------------------+

# +-------------------------------------------------------------+
class picidentifier (dict):
    signatures = ['\xe3\x19\x01\x00','\xc5\x3f\x01\x00','\x27\x00\x00\x00',\
                  '\x13Bit','d1:a','d1:r','d1:e','GNUT','GIV ','GND ',\
                  'GO!!','MD5 ','SIZ\x20']

    def __init__ (self,d={},dshort=5,dlong=(10*60),P=40,B=10000):
        # maybe include switches for identification behavior
        dct = {'dshort':dshort,'dlong':dlong,'P':P,'B':B}
        for k,v in dct.items():
            setattr(self,k,v)
        dict.__init__(self,d)

    def __hash__ (self):
        return id(self)

    def __str__ (self):
        s = ''
        for k,v in self.items():
            s += "%s: %s\n" % (k,v)
        return s[:-1]

    def _recent_ (self,ts,rec):
        delta = self.dlong if rec[1] else self.dshort
        return abs(ts-rec[0]) <= delta

    def _have_recent_entries_ (self,flo):
        ts = flo.lastaccess
        src = (flo.sip,flo.sport)
        dst = (flo.dip,flo.dport)
        val_src = None
        val_dst = None
        recent_src = False
        recent_dst = False
        certain_src = False
        certain_dst = False
        if self.has_key(src):
            val_src = self[src]
            recent_src = self._recent_(ts,val_src)
            certain_src = val_src[1]
        if self.has_key(dst):
            val_dst = self[dst]
            recent_dst = self._recent_(ts,val_dst)
            certain_dst = val_dst[1]
        return (recent_src,certain_src),(recent_dst,certain_dst)

    def _update_flow_ (self,flo,certain):
        ts = flo.lastaccess
        src = (flo.sip,flo.sport)
        dst = (flo.dip,flo.dport)
        self[src] = (ts,certain)
        self[dst] = (ts,certain)
        if certain:
            flo.ftype = TYPE['P2P']
            return True
        else:
            flo.ftype = TYPE['POSSIBLE']
            return False

    def identify (self,flo):
        recent_certain_src,recent_certain_dst = self._have_recent_entries_(flo)
        if flo.payload in self.signatures:
            return self._update_flow_(flo,True)
        if flo.protocol == IP_PROTO_TCP:
            if recent_certain_src[0] or recent_certain_dst[0]:
                return self._update_flow_(flo,True)
            else:
                return False
        elif flo.protocol == IP_PROTO_UDP:
            if (recent_certain_src[0] and recent_certain_src[1])\
            or (recent_certain_dst[0] and recent_certain_dst[1]):
                return self._update_flow_(flo,True)
            if flo.npackets > self.P or flo.nbytes > self.B:
                flo.ftype = TYPE['NONP2P']
                return True
            return self._update_flow_(flo,False)
        else:
            flo.ftype = TYPE['NONP2P']
            return True
        
    def summary (self):
        certain = sum(map(lambda x: 1 if x[1] else 0,self.values()))
        entries = len(self)
        uncertain = entries - certain
        keys = self.keys()
        ips = set([k[0] for k in keys])
        ports = set([k[1] for k in keys])
        s = "IDENTIFICATION SUMMARY\nentries: %s\ncertain: %s\nuncertain: %s\nips: %s\nports: %s" \
            % (entries,certain,uncertain,len(ips),len(ports))
        return s
# +-picidentifier-----------------------------------------------+
# EOF
