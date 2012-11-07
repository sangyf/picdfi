"""Cisco HDLC decapsulation

author:: thomas.zink
changelog::
	20091202 initial version
"""

import struct
import dpkt, stp
import sys

CHDLC_HDRLEN 		= 4
CHDLC_UNICAST		= 0x0f
CHDLC_BCAST			= 0x8f
CHDLC_TYPE_SLARP	= 0x8035
CHDLC_TYPE_CDP		= 0x2000
CHDLC_TYPE_IP		= 0x0800

"""
Address	Control	Protocol Code	Information	Frame Check Sequence (FCS)	Flag
8 bits	8 bits	16 bits	Variable length, 0 or more bits, in multiples of 8	16 bits	8 bits
"""

class Chdlc(dpkt.Packet):
	__hdr__ = (
		('addr', 'c', ''),
		('control', 'c', ''),
		('type', 'H', CHDLC_TYPE_IP)
	)
	
	_typesw = {}
	
	def _unpack_data(self, buf):
		try:
			self.data = self._typesw[self.type](buf)
			setattr(self, self.data.__class__.__name__.lower(), self.data)
		except (KeyError, dpkt.UnpackError):
			print >> sys.stderr, "KeyError %s" % dpkt.UnpackError
			self.data = buf
	
	def unpack(self, buf):
		dpkt.Packet.unpack(self, buf)
		if self.type == CHDLC_TYPE_IP:
			self._unpack_data(self.data)
	
	def set_type(cls, t, pktclass):
		cls._typesw[t] = pktclass
	set_type = classmethod(set_type)

	def get_type(cls, t):
		return cls._typesw[t]
	get_type = classmethod(get_type)

def __load_types():
	import os
	d = dict.fromkeys([ x[:-3] for x in os.listdir(os.path.dirname(__file__) or '.') if x.endswith('.py') ])
	g = globals()
	for k, v in g.iteritems():
		if k.startswith('CHDLC_TYPE_'):
			name = k[11:]
			modname = name.lower()
			if modname in d:
				mod = __import__(modname, g)
				Chdlc.set_type(v, getattr(mod, name))

if not Chdlc._typesw:
	__load_types()
	#print Chdlc._typesw

if __name__ == '__main__':
	import unittest
