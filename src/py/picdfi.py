#!/usr/bin/env python
"""
 * Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)
 * 
 * This is free Software. It can be used under the terms of the most
 * current version of the Lesser General Public License (LGPL).
 * Provided as is and NO WARRANTIES OR GUARANTEES OF _ANY_ KIND!
 * See the GNU General Public License for more details.

Python Flow Indentification

Provides a similar interface as tcpdump for capturing
packets or read capture files.

Captured packets are added to a packet queue which is processed by the flow table.

The flow table extracts a flow ID from the packet. A flow id can be extracted in a user
defined way by writing flow id extractors. The default extractor is a 5-tuple
of { src IP, dst IP, src Port, dst Port, Protocol }. The corresponding flow is then
updated using the packets information.

The flow table ages every A seconds, that is, flows that have not been accessed
for A seconds are removed from the table and added to an aged list. This list
can then be further processed, at the moment it is kept in memory.

Flows that have been created or modified are added to a flow queue which is processed
by the flow identifier. It tries to identify every unidentified flow and updates flow
information.

The flow table, aging and flow identification all run in dedicated threads for performance
reasons.

To capture files the library pylibpcap is used. See
http://sourceforge.net/projects/pylibpcap/

pylibpcap itself is a wrapper for libpcap / winpcap. These must be installed before
installing pylibpcap. See
http://www.tcpdump.org

In addition, pylibpcap depends on python development files. Under Linux install
python-dev package.

Decoding packets is done using dpkt. See
http://code.google.com/p/dpkt/

dpkt is written for python < 2.4. If using python2.6 compilation an installation
will fail due to syntax errors. In this case the file
./dpkt/bgp.py
has to be edited and the lines
678, 715
uncommented or removed.

These modules must be installed prior of running this application.

Author=Thomas Zink
Email=thomas.zink@uni-konstanz.de
Institude=Uni Konstanz
Description=flow identification for python
"""
# +-------------------------------------------------------------+
# |-IMPORTS-----------------------------------------------------|
# +-------------------------------------------------------------+
# standard python libs
import getopt, sys, os
import time
import compileall
from optparse import OptionParser
from operator import *
# dpkt and pcap libs
import dpkt
import pcap
# project libs
from utility import *
from patterns import *
from pic import *
from verification import *

# compile everything to object files to make it faster
compileall.compile_dir(os.getcwd(),force=True,quiet=True)

# +-------------------------------------------------------------+
# FUNCTIONS
# +-------------------------------------------------------------+

# +-------------------------------------------------------------+
def main (argv):
    """main(argv) -- main function
    
    checks command line arguments
    runs the specified functions
    """
    try:
        opts,args = check_argv(argv)
    except SystemExit:
        print >> sys.stderr, "bye"
        return
    return consolemain (opts,args)
# +-main--------------------------------------------------------+

# +-------------------------------------------------------------+
def consolemain (opts,args):
    """consolemain(opts,args)
    depending on command line arguments and options creates the packet handler
    and flowtable/identification objects and runs the simulations in an interactive
    console.
    """
    flist = []
    # check args
    if opts.vfile != '' or opts.nfile != '':
        verify = picverification(vfile = opts.vfile, nfile = opts.nfile)
        flowhandler = flowverifier(verify)
    else:
        verify = None
        flowhandler = flowdestroyer()
    if opts.dumpfile != '':
        flowhandler = flowserializer (fname=opts.dumpfile)
    # check if we got a single file to process
    if opts.ifile != '':
        flist += [opts.ifile]
    # check if we got a path to process
    if opts.ipath != '':
        if not opts.ipath.endswith(os.sep):
            opts.ipath += os.sep
        flist += [add(opts.ipath,x) for x in os.listdir(opts.ipath)]
    # check if we got a file list to process
    if opts.ilist != '':
        ilist = open(opts.ilist,'r')
        flist += ilist.read().split('\n')
        ilist.close()
    # create flowtable, identifier
    ftab = picflowtable(A=opts.A,handler=flowhandler)
    ident = picidentifier(dshort=opts.short,dlong=opts.long,P=opts.P,B=opts.B)
    # changed to support flist processing
    start = time.time()
    if len(flist) > 0:
        for f in flist:
            print "Process file: %s" % (f)
            pcapo = pcap.pcapObject()
            pcapo.open_offline(f)
            pcapo.setfilter(' '.join(args),0,0)
            pcaphandler = packethandler(opts=opts,DLT=pcapo.datalink(),ftab=ftab,ident=ident)
            # do it until EOF or SIGINT
            try:
                pcapo.loop(0,pcaphandler)
            except KeyboardInterrupt:
                break
    else:
        pcapo = pcap.pcapObject()
        pcapo.open_live(opts.dev,opts.snaplen,opts.promisc,opts.to_ms)
        pcapo.setfilter(' '.join(args),0,0)
        pcaphandler = packethandler(opts=opts,DLT=pcapo.datalink(),ftab=ftab,ident=ident)
        try:
            pcapo.loop(0,pcaphandler)
        except KeyboardInterrupt:
            pass
    # shut down
    print 'shutting down'
    print '%d packets received, %d packets dropped, %d packets dropped by interface' % pcapo.stats()
    print 'processed in %s' % (time.time()-start)
    if opts.ofile != '':
        handler.writer.close()
    if verify and opts.dumpfile != '':
        verify.verifyfile(opts.dumpfile)
    return ftab,ident,pcapo,verify
# +-consolemain-------------------------------------------------+

# +-------------------------------------------------------------+
def check_argv(argv):
    """check_agrv(argv) -- (options,arguments)
    
    parse command line arguments and options.
    return the arguments as string and an options object with switches.
    """
    # create parser
    optpar = OptionParser()
    # add options
    optpar.add_option(\
        '-r','--ifile',dest='ifile',\
        default='',\
        help='pcap input file\ndefault: ""')
    optpar.add_option(\
        '-R','--ipath',dest='ipath',\
        default='',\
        help='process multiple files int path R\ndefault: ""')
    optpar.add_option(\
        '-l','--ilist',dest='ilist',\
        default='',\
        help='process files from list l\ndefault: ""')
    optpar.add_option(\
        '-i','--iface',dest='dev',\
        default=pcap.lookupdev(),\
        help='listen interface. default: pcap_lookupdev()')
    optpar.add_option('-s','--snaplen',type='int',dest='snaplen',\
        default=1600,\
        help='snaplen, how many bytes to capture for each packet. default: 1600')
    optpar.add_option('-p','--promisc',dest='promisc',\
        action="store_false",default=True,\
        help='dont put interface into promiscuous mode')
    optpar.add_option('-v',dest='v',type='int',\
        default=1,\
        help='verbosity, 0 for number of packets, 1 for packets, 2 for packets and hexdump. default: 1')
    optpar.add_option('-m','--toms',type='int',dest='to_ms',\
        default=100,\
        help='to ms, read timeout in milliseconds. default: 100')
    optpar.add_option('-w','--ofile',dest='ofile',\
        default='',\
        help='pcap output file\ndefault: ""')
    optpar.add_option('-A','',type='int',dest='A',\
        default=30,\
        help='aging, at which intervals the flow table performs aging. default: 30')
    optpar.add_option('-P','',type='int',dest='P',\
        default=30,\
        help='packet threshold, how many packets are allowed in a P2P UDP flow. default: 30')
    optpar.add_option('-B','',type='int',dest='B',\
        default=30000,\
        help='byte threshold, how many bytes are allowed in a P2P UDP flow. default: 30000')
    optpar.add_option('','--short',type='int',dest='short',\
        default=5,\
        help='short delta, how many seconds is an uncertain flow kept for identification. default: 5')
    optpar.add_option('','--long',type='int',dest='long',\
        default=600,\
        help='long delta, how many seconds is a certain flow kept for identification. default: 600')
    optpar.add_option('-f','--vfile',dest='vfile',\
        default='',\
        help='openDPI verification file')
    optpar.add_option('-F','--nfile',dest='nfile',\
        default='',\
        help='host verification file')
    optpar.add_option('-o','--dumpfile',dest='dumpfile',\
        default='',\
        help='flow serialization file')
    # perform parsing
    opts,args = optpar.parse_args(argv)
    return opts,args
# +-checkargv---------------------------------------------------+

# +-------------------------------------------------------------+
def printtofile ():
    """printtofile() -- writes output to output.txt"""
    fd = open('output.txt','a')
    print >> fd, ' '.join(sys.argv[1:])
    print >> fd, ftab.summary()
    print >> fd, ident.summary()
    print >> fd, "+-------------------------------------------------------------+"
    fd.close()
# +-------------------------------------------------------------+   
if __name__=="__main__":
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass
    ret = main(sys.argv[1:])
    if ret != None:
        ftab,ident,p,verify = ret
        print ' '.join(sys.argv[1:])
        print
        print ftab.summary()
        print
        print ident.summary()
        print
        print verify.summary()
        print "+-------------------------------------------------------------+"
# +-------------------------------------------------------------+
# EOF
