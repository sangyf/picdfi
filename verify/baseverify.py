#!/usr/bin/env python
'''
Parsing, Baseline and verification

This script can parse result files from nDPI, SPID and picDFI.
It also builds a baseline using the results of nDPI and SPID.
This baseline can be used to evaluate the results of picDFI.
Evaluation also computes and can output standard metrics.
Finally, the script outputs flow ids and tcpdump filter strings of disputable flows.
These can directly be used in bash scripts to inspect these flows.

Howto generate result.

'''

# TODO: implement evaluater, uses baseline to compare picdfi results

import sys, os
import struct, socket
from operator import add, div, mul, sub
from math import sqrt

# picdfi types for evaluation
picdfi_type_unidentified = 0x00
picdfi_type_p2p = 0x02
picdfi_type_nonp2p = 0x04

### helper functions ##########################################################

def aton(a): return struct.unpack("!L",socket.inet_aton(a))[0]
def ntoa(n): return socket.inet_ntoa(struct.pack("!L", n))

def openfile(fname):
    fhandle = None
    try: fhandle = open(fname,'r')
    except IOError as e: print e
    return fhandle

def dfi(fhandle):
    results = []
    flows = []
    for line in fhandle:
        if line.startswith("TOTAL"): continue
        if line.startswith("UNIDENTIFIED"): continue
        s = line.split()
        # label, pkt, bytes, flows on [0,2,4,6]
        results.append(result(s[0],s[2],s[4],s[6]))
    fhandle.close()
    return results, flows

### RESULT AND FLOW CLASSES ###################################################
class result(object):
    def __init__ (self,label,packets,bytes,flows):
        self.label = label
        self.packets = int(packets)
        self.bytes = int(bytes)
        self.flows = int(flows)

    def __str__ (self):
        return str(self.label) + "," + str(self.packets) + "," + str(self.bytes) + "," + str(self.flows)

    def __add__ (self,other):
        self.packets += other.packets
        self.bytes += other.bytes
        self.flows += other.flows

    def __repr__ (self):
        return str(self)

class flowid(object):
    def __init__(self,la,lp,ua,up,proto):
        if aton(la) > aton(ua):
            self.la = str(ua)
            self.lp = int(up)
            self.ua = str(la)
            self.up = int(lp)
        else:
            self.la = str(la)
            self.lp = int(lp)
            self.ua = str(ua)
            self.up = int(up)
        try:
            self.p = int(proto)
        except ValueError:
            p = str(proto).lower()
            if p == "tcp": self.p = 0x06
            elif p == "udp": self.p = 0x11

    def __hash__(self):
        return hash((self.la,self.lp,self.ua,self.up,self.p))

    def __eq__(self,o):
        return (self.la,self.lp,self.ua,self.up,self.p) == (o.la,o.lp,o.ua,o.up,o.p)

    def __str__(self):
        return str(self.la) + "," + str(self.lp) + "," + str(self.ua) + "," + str(self.up) + "," + str(self.p)

    def __repr__(self):
        return str(self)

class flowrecord(object):
    def __init__ (self,ts = 0,npkts = 1,nbytes = 1,ftype = picdfi_type_unidentified):
        self.ts = float(ts)
        self.npkts = int(npkts)
        self.nbytes = int(nbytes)
        self.ftype = int(ftype)

    def __str__ (self):
        return str(self.ts) + "," + str(self.npkts) + "," + str(self.nbytes) + "," + str(self.ftype)

    def __repr__ (self):
        return str(self)

    def update(self,rec):
        if rec.ts < self.ts: self.ts = rec.ts
        self.npkts += rec.npkts
        self.nbytes += rec.nbytes
        # influences flow type collisions in favor of first result
        # in examples often favors nonp2p over p2p
        if self.ftype == picdfi_type_unidentified and rec.ftype != picdfi_type_unidentified:
            self.ftype = rec.ftype

### CLASSIFIER CLASSES ########################################################
class classifier(object):
    results = []
    flows = {}
    lines = {} # map flowids to lines

    type_p2p = []
    type_unidentified = ''

    def __init__ (self, fname):
        fhandle = openfile(fname)
        if fhandle:
            self.results, self.flows, self.lines = self.parse(fhandle)
            fhandle.close()

    def parse(self,fhandle):
        return None,None

    def convert_to_picdfi_type(self,ftype):
        if ftype in self.type_p2p:
            return picdfi_type_p2p
        elif ftype == self.type_unidentified:
            return picdfi_type_unidentified
        return picdfi_type_nonp2p

    def serializeResults(self):
        s = "label,packets,bytes,flows\n"
        for r in self.results: s += str(r) + '\n'
        return s

    def serializeFlows(self):
        s = 'la,lp,ua,up,p,ts,nbytes,npkts,flowtype\n'
        for k,v, in self.flows.items(): s += str(k) + ',' + str(v) + '\n'
        return s


# nDPI
class nDPI(classifier):
    type_p2p = ['AppleJuice', 'DirectConnect','WinMX','iMESH','FastTrack','Gnutella','eDonkey','BitTorrent','Skype']
    type_unidentified = 'Unknown'

    def parse(self,fhandle):
        # result summary
        marker = "detected protocols"
        markerfound = False
        results = []
        for line in fhandle:
            if markerfound:
                s = line.split()
                if len(s) == 0: break
                results.append(result(s[0],s[2],s[4],s[6]))
            if line.lower().find(marker) != -1:
                markerfound = True
        # flows
        flows = {}
        lines = {}
        for line in fhandle:
            # flowid: protocol, la, lp, ua, up
            try: s = line[:line.index('[')].split()
            except: continue
            proto = s[0]
            la,lp = s[1].split(":")
            ua,up = s[3].split(":")
            s = line[line.index('['):].split("][")
            ftype = self.convert_to_picdfi_type(s[0].split('/')[1])
            pkts_bytes = s[1].split('/')
            npkts = pkts_bytes[0].split()[0]
            nbytes = pkts_bytes[1].split()[0]
            ts = 0
            fid = flowid(la,lp,ua,up,proto)
            rec = flowrecord(ts,npkts,nbytes,ftype)
            if flows.has_key(fid):
                flows[fid].update(rec)
            else:
                flows[fid] = rec
            if lines.has_key(fid): lines[fid].append(line)
            else: lines[fid] = [line]
        # cleanup and return
        #fhandle.close()
        return results, flows, lines

# SPID
class SPID(classifier):
    type_p2p = ['BitTorrent','eDonkey','eDonkeyTCPObfuscation','eDonkeyUDPObfuscation','MSE','SkypeTCP','SkypeUDP','SpotifyP2P']

    def parse(self,fhandle):
        # first read result summary
        marker = "# Identified protocols"
        markerfound = False
        results = []
        for line in fhandle:
            if markerfound:
                s = line.split()
                if len(s) == 1: break
                if s[1].find("[") != -1: continue
                results.append(result(s[1],0,0,s[2]))
            if line.find(marker) != -1:
                markerfound = True
        # now read flows
        flows = {}
        lines = {}
        for line in fhandle:
            if line.startswith("\n") or line.startswith("#"): continue
            s = line.split()
            la = s[0]
            lp = s[2]
            ua = s[3]
            up = s[5]
            p = s[1]
            ts = s[6]
            touched = ts
            nbytes = '0'
            npkts = s[7]
            if len(s)<9: typ = picdfi_type_unidentified
            else: typ = self.convert_to_picdfi_type(s[8])
            fid = flowid(la,lp,ua,up,p)
            rec = flowrecord(ts,npkts,nbytes,typ)
            if flows.has_key(fid):
                flows[fid].update(rec)
            else:
                flows[fid] = rec
            if lines.has_key(fid): lines[fid].append(line)
            else: lines[fid] = [line]
        return results, flows, lines

# picDFI
class picDFI(classifier):
    type_p2p = [str(picdfi_type_p2p)]
    type_unidentified = str(picdfi_type_unidentified)
    
    def parse(self,fhandle):
        # first flows, then result summary
        marker = 'Flow Table Summary'
        markerfound = False
        results = []
        flows={}
        lines={}
        for line in fhandle:
            # flows start with digits
            if not markerfound and line[0].isdigit():
                s = line.split(',')
                #typ = self.convert_to_picdfi_type(s[9])
                typ = int(s[9])
                fid = flowid(s[0],s[1],s[2],s[3],s[4])
                rec = flowrecord(s[5],s[7],s[8],typ)
                if flows.has_key(fid):
                    flows[fid].update(rec)
                else:
                    flows[fid] = rec
                if lines.has_key(fid): lines[fid].append(line)
                else: lines[fid] = [line]
            elif line.find(marker) != -1: markerfound = True
            elif markerfound:
                if line.startswith("TOTAL"): continue
                else:
                    s = line.split()
                    try: results.append(result(s[0],s[2],s[4],s[6]))
                    except IndexError: break
        # convert possible to nonp2p
        pos = None
        np2p = None
        for r in results:
            if r.label == "POSSIBLE": pos = r
            elif r.label == "NONP2P": np2p = r
        np2p += pos
        results = [x for x in results if x.label != "POSSIBLE"]
        return results, flows, lines

### BASELINE BUILDING / EVAL ##################################################

class verification(dict):
    def __init__(self):
        # init dictionary that maps true / false positives / negatives to counters of [nflows, npkts, nbytes]
        dict.__init__(self, {"na_positive":[[0,0,0],[]],"na_negative":[[0,0,0],[]],"true_positive":[[0,0,0],[]],"false_positive":[[0,0,0],[]],"true_negative":[[0,0,0],[]],"false_negative":[[0,0,0],[]]})

    def __addflow(self,key,fid,frec):
        v = self[key]
        v[0] = map(add,v[0],[1,frec.npkts,frec.nbytes])
        v[1].append(fid)
        
    def np(self,fid,frec):
        self.__addflow("na_positive",fid,frec)
    
    def nn(self,fid,frec):
        self.__addflow("na_negative",fid,frec)
    
    def tp(self,fid,frec):
        self.__addflow("true_positive",fid,frec)
    
    def fp(self,fid,frec):
        self.__addflow("false_positive",fid,frec)
    
    def tn(self,fid,frec):
        self.__addflow("true_negative",fid,frec)
    
    def fn(self,fid,frec):
        self.__addflow("false_negative",fid,frec)

    def stats(self):
        rounddivmap = lambda a,b: map(lambda x: round(x * 100,2) , map(div,a,b))
        sums1 = [float(a)+b+c+d+e+f for a,b,c,d,e,f in zip(self["true_positive"][0],self["false_positive"][0],self["true_negative"][0],self["false_negative"][0],self["na_positive"][0],self["na_negative"][0])]
        sums2 = [float(a)+b+c+d for a,b,c,d in zip(self["true_positive"][0],self["false_positive"][0],self["true_negative"][0],self["false_negative"][0])]
        s = "condition, nflows, npkts, nbytes, %flows, %pkts, %bytes\n"
        for k,v in self.items():
            rdivs1 = rounddivmap(v[0],sums1)
            rdivs2 = rounddivmap(v[0],sums2)
            #s += k + "& " + str(v[0])[1:-1] + "& " + str(rounddivmap(v[0],sums))[1:-1] + "\n"
            s += k
            for i in range(len(v[0])):
                s += " & " + str(v[0][i]) + " (" + str(rdivs1[i]) + "\%)" + " [" + str(rdivs2[i]) + "\%]"
            s += "\n"
        return s
        
    def metrics(self):
        percent = lambda a,b: round(a * 100 / b,2)
        ladd = lambda a,b: [x+y for x,y in zip(a,b)]
        lsub = lambda a,b: [x-y for x,y in zip(a,b)]
        ldiv = lambda a,b: [x/y for x,y in zip(a,b)]
        lmul = lambda a,b: [x*y for x,y in zip(a,b)]
        l4mul = lambda a,b,c,d: [w*x*y*z for w,x,y,z in zip(a,b,c,d)]

        tp = map(float,self["true_positive"][0])
        _2tp = [x * 2 for x in tp]
        fp = map(float,self["false_positive"][0])
        tn = map(float,self["true_negative"][0])
        fn = map(float,self["false_negative"][0])
        p = map(add,tp,fn)
        n = map(add,fp,tn)
        pn = map(add,p,n)
        
        recall = map(percent,tp,p) # true positive rate, hit rate, sensitivity
        specificity = map(percent,tn,n) # true negative, rate
        precision = map(percent,tp,map(add,tp,fp)) # positive predictive value ppv
        npv = map(percent,tn,map(add,tn,fn)) # negative predictive value
        accuracy = map(percent,map(add,tp,tn),pn)
        fscore = map(percent,_2tp,[x+y+z for x,y,z in zip(_2tp,fp,fn)]) # same as 2 * (precision * recall) / (precision + recall)
        mcc = map(percent, lsub(lmul(tp,tn),lmul(fp,fn)), map(sqrt,l4mul(ladd(tp,fp),ladd(tp,fn),ladd(tn,fp),ladd(tn,fn)))) # matthew's correlation coefficient
        
        s = "metric, flows, pkts, bytes\n"
        s += "recall, " + str(recall)[1:-1] + "\n"
        s += "specificity, " + str(specificity)[1:-1] + "\n"
        s += "precision, " + str(precision)[1:-1] + "\n"
        s += "npv, " + str(npv)[1:-1] + "\n"
        s += "accuracy, " + str(accuracy)[1:-1] + "\n"
        s += "fscore, " + str(fscore)[1:-1] + "\n"
        s += "mcc, " + str(mcc)[1:-1] + "\n"
        s = s.replace(',',' &').replace('\n',' \\\\\n') # latex friendly
        return s

    def metrics2(self):
        # counts NP as TP and NN as TF
        percent = lambda a,b: round(a * 100 / b,2)
        ladd = lambda a,b: [x+y for x,y in zip(a,b)]
        lsub = lambda a,b: [x-y for x,y in zip(a,b)]
        ldiv = lambda a,b: [x/y for x,y in zip(a,b)]
        lmul = lambda a,b: [x*y for x,y in zip(a,b)]
        l4mul = lambda a,b,c,d: [w*x*y*z for w,x,y,z in zip(a,b,c,d)]

        tp = map(float,map(add,self["true_positive"][0],self["na_positive"][0]))
        _2tp = [x * 2 for x in tp]
        fp = map(float,self["false_positive"][0])
        tn = map(float,map(add,self["true_negative"][0],self["na_negative"][0]))
        fn = map(float,self["false_negative"][0])
        p = map(add,tp,fn)
        n = map(add,fp,tn)
        pn = map(add,p,n)
        
        recall = map(percent,tp,p) # true positive rate, hit rate, sensitivity
        specificity = map(percent,tn,n) # true negative, rate
        precision = map(percent,tp,map(add,tp,fp)) # positive predictive value ppv
        npv = map(percent,tn,map(add,tn,fn)) # negative predictive value
        accuracy = map(percent,map(add,tp,tn),pn)
        fscore = map(percent,_2tp,[x+y+z for x,y,z in zip(_2tp,fp,fn)]) # same as 2 * (precision * recall) / (precision + recall)
        mcc = map(percent, lsub(lmul(tp,tn),lmul(fp,fn)), map(sqrt,l4mul(ladd(tp,fp),ladd(tp,fn),ladd(tn,fp),ladd(tn,fn)))) # matthew's correlation coefficient
        
        s = "metric, flows, pkts, bytes\n"
        s += "recall, " + str(recall)[1:-1] + "\n"
        s += "specificity, " + str(specificity)[1:-1] + "\n"
        s += "precision, " + str(precision)[1:-1] + "\n"
        s += "npv, " + str(npv)[1:-1] + "\n"
        s += "accuracy, " + str(accuracy)[1:-1] + "\n"
        s += "fscore, " + str(fscore)[1:-1] + "\n"
        s += "mcc, " + str(mcc)[1:-1] + "\n"
        s = s.replace(',',' &').replace('\n',' \\\\\n') # latex friendly
        return s
        
class baseline (object):
    base = None
    verified = verification()

    # uses a list of flows as baseline
    def __init__ (self,flows = None):
        self.addbaseline(flows)

    # adds a list of flows to the baseline
    def addbaseline(self,flows):
        if self.base == None:
            self.base = flows
        else:
            for fid,frec in flows.items():
                try:
                    record = self.base[fid]
                    if record.ftype == picdfi_type_unidentified and frec.ftype != picdfi_type_unidentified:
                        record.ftype = frec.ftype
                except KeyError: pass

    # verifies flows by comparing to baseline
    def verify(self,flows):
        for fid, frec in flows.items():
            it = None
            try:
                it = self.base[fid]
                # can't verify if base not identified
                if it.ftype == picdfi_type_unidentified:
                    if frec.ftype == picdfi_type_p2p:
                        self.verified.np(fid,frec)
                    else:
                        self.verified.nn(fid,frec)
                elif it.ftype == picdfi_type_p2p:
                    if frec.ftype == picdfi_type_p2p:
                        self.verified.tp(fid,frec)
                    else:
                        self.verified.fn(fid,frec)
                elif it.ftype == picdfi_type_nonp2p:
                    if frec.ftype == picdfi_type_p2p:
                        self.verified.fp(fid,frec)
                    if frec.ftype == picdfi_type_nonp2p:
                        self.verified.tn(fid,frec)
            except KeyError:
                if frec.ftype == picdfi_type_p2p:
                    self.verified.np(fid,frec)
                else:
                    self.verified.nn(fid,frec)
                    

### MAIN ######################################################################

def fid2tcpdump(fname,fid):
    proto = "TCP" if fid.p==0x06 else "UDP"
    #s = "echo flow id %s\n" %fid
    s = ''
    s += "tcpdump -r %s -n -X host \\(%s and %s\\) and port \\(%s and %s\\) and proto %s" % (fname,fid.la, fid.ua, fid.lp, fid.up, proto) 
    return s

def printTcpdumpFlows(fname,verified):
    for cond in ['true','false','na']:
        for outcome in ['positive','negative']:
            field = '%s_%s' % (cond,outcome)
            print "%s Flows" % (field)
            for fid in verified[field][1]:
                print fid2tcpdump(fname,fid)
            print
            

def testhasheq(flows):
    n = flows.keys()[0]
    f = flowid(n.la,n.lp,n.ua,n.up,n.p)
    print "n:", n, "hash(n)", hash(n)
    print "f:", f, "hash(f)", hash(f)
    print "n == f", n == f

def main(argv):
    klas = None
    ndpi = None
    spid = None
    pic = None
    fnames = ["spid.txt", "ndpi.txt", "picdfi.txt"]

    # parse files
    for fname in fnames:
        print "Parsing", fname
        if fname.find("ndpi") != -1:
            ndpi = nDPI(fname)
            klas = ndpi
        elif fname.find("spid") != -1:
            spid = SPID(fname)
            klas = spid
        elif fname.find("picdfi") != -1:
            pic = picDFI(fname)
            klas = pic

    # build baseline
    print "Building Baseline ..."
    base = baseline(ndpi.flows)
    base.addbaseline(spid.flows)
    print "Verify flows ..."
    print
    base.verify(pic.flows)
    print base.verified.stats()
    print
    print base.verified.metrics()
    print
    print "With NP added to TP and NN added to TF"
    print base.verified.metrics2()
    print

    try:
        fname = argv[1]
        printTcpdumpFlows(fname,base.verified)
    except IndexError:
        pass
    
if __name__ == '__main__':
    main(sys.argv)
    
