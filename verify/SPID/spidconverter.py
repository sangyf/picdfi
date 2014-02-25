#!/usr/bin/env python
'''
Converts a SPID result file to a PICDFI verification file.
SPID results have the following format:

[clientIp]	[clientPort]	[serverIp]	[serverPort]	[sessionStartTime]	[inspectedFramesWithPayload]	[identifiedProtocol]
134.34.10.37	TCP 1407	209.85.129.99	TCP 80	        1251388105.540541000	10	                        HTTP

PICDFI verification files must have the format:

lower_ip,lower_port,upper_ip,upper_port,protocol,created ts,touched ts,npackets,nbytes,flowtype\n
134.34.10.38,57763,134.34.3.2,53,17,1244542904.09,1244542904.44,3,280,1

Some information is not given by SPID, like number of bytes or the last touched ts.
Also we need to convert to PICDFI types

enum picdfi_type {
	type_unidentified = 0x00,
	type_possible = 0x01,
	type_p2p = 0x02,
	type_nonp2p = 0x04
};
'''


import sys,os
import socket,struct

def aton(a): return struct.unpack("!L",socket.inet_aton(a))[0]
def ntoa(n): return socket.inet_ntoa(struct.pack("!L", n))

picdfi_type_unidentified = 0x00
picdfi_type_p2p = 0x02
picdfi_type_nonp2p = 0x04


if __name__=="__main__":
    # check parameter for file name
    if len(sys.argv)<2:
        print "Usage: ./spidconverter.py <spid result file>"
        sys.exit(-1)

    fname = sys.argv[1]
    handle = None
    try: handle = open(fname)
    except IOException as e:
        print e
        sys.exit(-1)

    for line in handle:
        if line.startswith("\n") or line.startswith("#"): continue
        s = line.split()
        la = s[0]
        lp = s[2]
        ua = s[3]
        up = s[5]
        p = s[1]
        ts = s[6]
        touched = ts
        nbytes = 0
        npkts = s[7]
        typ = picdfi_type_unidentified
        if aton(s[0]) > aton(s[3]):
            la = s[3]
            lp = s[5]
            ua = s[0]
            up = s[2]
        # convert type # BitTorrent # eDonkey # eDonkeyTCPObfuscation # eDonkeyUDPObfuscation # MSE # SkypeTCP # SkypeUDP # SpotifyP2P
        
        if len(s)<9: pass
        elif s[8]=='BitTorrent':
            typ = picdfi_type_p2p
        else:
            typ = picdfi_type_nonp2p
            
        
