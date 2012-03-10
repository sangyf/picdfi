Copyright 2010-2011 Thomas Zink (thomas.zink < at > uni < dot > kn)

This is free Software. It can be used under the terms of the most
current version of the [Lesser General Public License][lgpl] (LGPL).
Provided as is and NO WARRANTIES OR GUARANTEES OF ANY KIND! See the GNU General Public License for more details.

# PICDFI - Deep Flow Inspection on Physical Interface Cards ##################

This program implements a very simple behavior based algorithm to classify
network flows as either _P2P_, _Non-P2P_ or _Unidentified_. It is a proof of
concept implementation. The algorithm is actually intended to be used directly
in hardware on the PIC level.

Run 'make' to build. Use 'man ./picdfi.1' to read the manual page.


[lgpl]: http://www.gnu.org/copyleft/lesser.html "LGPL"