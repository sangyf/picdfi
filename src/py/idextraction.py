"""
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.

Flow ID extraction classes

implements interfaces and classes used to extract flow ids from packets.
all id extractors are derieved from the abstract class flowidextractor.
"""

__all__ = ["flowidextractor","bi5tuple","uni5tuple"]

# +-------------------------------------------------------------+
# IMPORTS
# +-------------------------------------------------------------+

from patterns import *
import struct
import sys
import pcap

# +-------------------------------------------------------------+
# CLASSES
# +-------------------------------------------------------------+

# +-------------------------------------------------------------+
class flowidextractor (abstractbaseclass):
    """abstract flow ID extractor class
    
    is called directly via self.__call__. to implement
    ID extractors use this base class and implement 
    the method _extractID_ which is called by __call__.
    a flow id extractor should return None if no id can
    be extracted. The packet must be decoded using
    dpkg.ethernet.Ethernet
    """
    def __init__ (self): pass
    
    def __call__ (self,p):
        """__call__ (packet) -> extracted ID, int"""
        fid = None
        try:
            fid = self._extractID_ (p)
        except AttributeError, e:
            print >> sys.stderr, "ID extraction error: %s" % e
        return fid
    
    def _extractID_ (self,p):
        """__extractID (p) -> extracted ID from p, int"""
        abstract()
# |-flowidextractor---------------------------------------------|

# +-------------------------------------------------------------+
class bi5tupleframe (flowidextractor,singleton):
    """5-tuple bi-directional flow ID extractor
    
    extract a standard 5-tuple {protocol,sip,dip,sport,dport}
    as flow id from the packet. The smaller IP is used as first
    part of the tuple, such every flow is BI-directional.
    """
    def __init__ (self): pass
    
    def _extractID_ (self,p):
        eth = p[1]
        buf = str(eth)
        sip = struct.unpack('!L',eth.data.src)[0]
        dip = struct.unpack('!L',eth.data.dst)[0]
        sport = eth.data.data.sport
        dport = eth.data.data.dport
        p = eth.data.p
        if sip <= dip:
                s = "%d%d%d%d%d" % (sip,sport,dip,dport,p)
        else:
                s = "%d%d%d%d%d" % (dip,dport,sip,sport,p)
        fid = hash(int(s))
        return fid
# |-bi5tuple----------------------------------------------------|

# +-------------------------------------------------------------+
class bi5tuple (flowidextractor,singleton):
    """5-tuple bi-directional flow ID extractor
    
    extract a standard 5-tuple {protocol,sip,dip,sport,dport}
    as flow id from the packet. The smaller IP is used as first
    part of the tuple, such every flow is BI-directional.
    """
    def __init__ (self): pass
    
    def _extractID_ (self,p):
        ippkt = p[1]
        buf = str(ippkt)
        sip = struct.unpack('!L',ippkt.src)[0]
        dip = struct.unpack('!L',ippkt.dst)[0]
        sport = ippkt.data.sport
        dport = ippkt.data.dport
        p = ippkt.p
        if sip <= dip:
                s = "%d%d%d%d%d" % (sip,sport,dip,dport,p)
        else:
                s = "%d%d%d%d%d" % (dip,dport,sip,sport,p)
        fid = hash(int(s))
        return fid
# |-bi5tuple----------------------------------------------------|

# +-------------------------------------------------------------+
class uni5tupleframe (flowidextractor,singleton):
    """5-tuple uni-directional flow ID extractor
    
    extract a standard 5-tuple {protocol,sip,dip,sport,dport}
    as flow id from the packet. Flows are uni directional,
    meaning return packets are not considered part of the
    same flow.
    """
    def __init__ (self): pass
        
    def _extractID_ (self,p):
        eth = p[1]
        buf = str(eth)
        sip = struct.unpack('!L',eth.data.src)[0]
        dip = struct.unpack('!L',eth.data.dst)[0]
        sport = eth.data.data.sport
        dport = eth.data.data.dport
        p = eth.data.p
        s = "%d%d%d%d%d" % (sip,sport,dip,dport,p)
        fid = hash(int(s))
        return fid
# |-uni5tuple---------------------------------------------------|

# +-------------------------------------------------------------+
class uni5tuple (flowidextractor,singleton):
    """5-tuple uni-directional flow ID extractor
    
    extract a standard 5-tuple {protocol,sip,dip,sport,dport}
    as flow id from the packet. Flows are uni directional,
    meaning return packets are not considered part of the
    same flow.
    """
    def __init__ (self): pass
        
    def _extractID_ (self,p):
        ippkt = p[1]
        buf = str(ippkt)
        sip = struct.unpack('!L',ippkt.src)[0]
        dip = struct.unpack('!L',ippkt.dst)[0]
        sport = ippkt.data.sport
        dport = ippkt.data.dport
        p = ippkt.p
        s = "%d%d%d%d%d" % (sip,sport,dip,dport,p)
        fid = hash(int(s))
        return fid
# |-uni5tuple---------------------------------------------------|

# EOF
