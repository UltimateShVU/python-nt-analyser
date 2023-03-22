import sys
import argparse

from pylibpcap import get_iface_list
from pylibpcap import get_first_iface
from pylibpcap.base import Sniff

import sniff
from sniff import *

import analyze
from analyze import *
 
def createParser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-iL', '--ifacelist', action='store_const', const=True, help='Get list of ifaces and exit') #Get list of ifaces and exit
    parser.add_argument('iface', nargs='?', help='Custom iface for sniffing') #Custom iface for sniffing
    parser.add_argument('--nopcap', action='store_const', const=True, help='Don\'t create pcap file') #Don't create pcap file
    parser.add_argument('-pcap', '--pcap', default='pcap.pcap', help='Custom pcap-file to write to') #Custom pcap-file to write to
    parser.add_argument('-c', '--count', type=int, default=-1, help='How many packets will be captured. When non provided, keep capturing until program closed') #How many packets should we capture? Default: INF
    
    return parser    
      
def capt(sniffobj):
    for plen, t, buf in sniffobj.capture():
        try:
            packet = getFriendlyPacket(plen, t, buf)
            #print(t, "  ", packet['sip'], " ->  ", packet['dip'], " :   ", packet['data'])
            print(t, packet)
        except Exception:
            print("\n")
            print("Error occured while packet analyzing:")
            print(sys.exc_info())  
            print("\n")
            continue

def main_func(iface, of, c):
    try:
        sniffobj = Sniff(iface, out_file=of, count=c)
        capt(sniffobj)
    except Exception:
        print(sys.exc_info())   



if __name__ == '__main__':
    parser = createParser()
    args = parser.parse_args()
    if args.ifacelist:
        for i in get_iface_list():
            print(i)
        sys.exit()
    iface = args.iface or get_first_iface()
    pcap = args.pcap
    if args.nopcap:
        pcap = "pcap.pcap"
    count=args.count
    main_func(iface, pcap, count)


