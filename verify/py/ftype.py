"""
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.
"""
__all__ = ['TYPE']

# +-------------------------------------------------------------+
# GLOBALS
# +-------------------------------------------------------------+

TYPE = {}
def _def_type(name,code):
    TYPE[name]=code
    TYPE[code]=name
_def_type('UNIDENTIFIED',0x00)
_def_type('POSSIBLE',0x01)
_def_type('P2P',0x02)
_def_type('NONP2P',0x04)

# +-------------------------------------------------------------+
# EOF
