Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)

This is free Software. It can be used under the terms of the most
current version of the [Lesser General Public License][lgpl] (LGPL).
Provided as is and NO WARRANTIES OR GUARANTEES OF ANY KIND! See the GNU General Public License for more details.

# PICDFI - Deep Flow Inspection on Physical Interface Cards ##################

This program implements a very simple behavior based algorithm to classify
network flows as either _P2P_, _Non-P2P_ or _Unidentified_. It is a proof of
concept implementation. The algorithm is actually intended to be used directly
in hardware on the PIC level.

There are two implementations available, one in c (/src/c) and one in python (/src/py). The c
version is newer, more optimized and obviously much faster. The python version represents an
initial testing prototype.

For the c version run 'make' to build. Use 'man ./picdfi.1' to read the manual page.
The python version can be executed with ./picdfi and options.

There is a [TechReport available][techreport] with detailed information and documentation about the algorithm
and implementation.

## Verification

picDFI supports verification files to verify classification results. These can be generated with other classification
tool like [OpenDPI][opendpi]. The directory 'verification' contains implementations to create verification files and
entries. One is a program that uses OpenDPI to classify packets, converts the results to picDFI flow classes and then
writes a verification file. The dir 'verification/py' hosts scripts that use OS commands to look at running programs
to create verification entries. They have to be executed on the hosts running the programs that should be classified.

## Dependencies

You need to have pcap installed. If you want to use the OpenDPI verification program, you also need to have the OpenDPI
library installed, which unfortunately is now unavailable. But there are several snapshots floating around.

For the python version you also need to have python pcap wrappers. The program is designed to run with [pylibpcap][pypcap].

[lgpl]: http://www.gnu.org/copyleft/lesser.html "LGPL"
[techreport]: http://nbn-resolving.de/urn:nbn:de:bsz:352-188702 "Analysis and efficient classification of P2P file sharing traffic"
[opendpi]: http://www.opendpi.org/ "OpenDPI"
[pypcap]: http://sourceforge.net/projects/pylibpcap/ "pylibpcap"
