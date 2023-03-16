import sys

from pylibpcap import get_iface_list
from pylibpcap import get_first_iface
from pylibpcap.base import Sniff

import sniff
from sniff import *

import analyze
from analyze import *

def arg_parser():
    print(get_iface_list())
    return
        
def main_func(sniffobj):
    for plen, t, buf in sniffobj.capture():
        packet = getFriendlyPacket(buf)
        print(t, "  ", packet['sip'], " ->  ", packet['dip'], " :   ", packet['data'])
        #print(t, packet)
        
if "-si" in sys.argv:        
    arg_parser()
elif len(sys.argv) > 1:
    try:
        sniffobj = getSniffObj(sys.argv[1])
        main_func(sniffobj)
    except Exception:
        print(sys.exc_info())
else:
    try:
        sniffobj = getSniffObj(get_first_iface())
        main_func(sniffobj)

#        stats = sniffobj.stats()
#        print(stats.capture_cnt, " packets captured")
#        print(stats.ps_recv, " packets received by filter")
#        print(stats.ps_drop, "  packets dropped by kernel")
#        print(stats.ps_ifdrop, "  packets dropped by iface")
    except Exception:
        print(sys.exc_info())
