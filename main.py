import sys, signal
import argparse
from pylibpcap      import get_iface_list, get_first_iface
from pylibpcap.base import Sniff
from analyze        import analyze_packet_verdict
from analyze_defs   import SIGINT

keep_running = 1

# SIGINT (CTRL+C) signal handling
def helper_signal_handler(signum, frame):
    if (SIGINT == signum):
        global keep_running
        keep_running = 0

def main_parser_create():
    parser = argparse.ArgumentParser()
    parser.add_argument('-iL', '--ifacelist', action='store_const', const=True, help='Get list of ifaces and exit') # Get list of ifaces and exit
    parser.add_argument('-i', '--iface', nargs='?', help='Custom iface for sniffing') #Custom iface for sniffing
    parser.add_argument('--nopcap', action='store_const', const=True, help='Don\'t create pcap file') #Don't create pcap file
    parser.add_argument('-p', '--pcap', default='dump.pcap', help='Custom pcap-file to write to') #Custom pcap-file to write to
    parser.add_argument('-c', '--count', type=int, default=-1, help='How many packets will be captured. When non provided, keep capturing until program closed') #How many packets should we capture? Default: INF

    return parser

def main_capture_packets(sniff_obj) -> None:
    global keep_running

    for plen, t, buf in sniff_obj.capture():
        try:
            if keep_running:  
                packet = analyze_packet_verdict(plen, t, buf)
                if packet:
                    print(packet["verdict"], "|", packet["time"], "|", packet["payload"], "|", packet["description"], "|")
            else:
                break
        except Exception:
            print("\nError occured while packet analyzing:")
            print(sys.exc_info())
            continue
    
    if not keep_running:
        sys.exit(0)

def main_loop(iface, of, c) -> None:
    try:
        sniffobj = Sniff(iface, out_file=of, count=c)
        main_capture_packets(sniffobj)
    except Exception:
        print(sys.exc_info())

def main_ifaces_banner() -> None:
    print("The system has the following interfaces:")
    print("+--- LIST ---+")
    print("\n".join(get_iface_list()))
    print("+------------+")

if __name__ == '__main__':
    signal.signal(signal.SIGINT, helper_signal_handler)
    parser = main_parser_create()
    args = parser.parse_args()

    if args.ifacelist:
        main_ifaces_banner()
        sys.exit()

    iface = args.iface or get_first_iface()
    pcap = args.pcap

    if args.nopcap:
        pcap = ""
    
    count = args.count

    main_loop(iface, pcap, count)