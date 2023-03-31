import sys, signal
import argparse
from pylibpcap      import get_iface_list, get_first_iface
from pylibpcap.base import Sniff
from analyze        import analyze_packet_verdict
from analyze_defs   import SIGINT
from complex        import complexAnalysis, stop_analysis

# SIGINT (CTRL+C) signal handling
def helper_signal_handler(signum, frame):
    if (SIGINT == signum):
        stop_analysis()

def main_parser_create():
    parser = argparse.ArgumentParser()
    # Get list of ifaces and exit
    parser.add_argument('-iL', '--ifacelist', action='store_const', const=True, help='Get list of ifaces and exit')
    # Set custom iface for sniffing
    parser.add_argument('-i', '--iface', nargs='?', help='Custom iface for sniffing')
    # Don't create pcap file
    parser.add_argument('--nopcap', action='store_const', const=True, help='Don\'t create pcap file')
    # Set custom pcap-file to write traffic dump to it on the setted interface
    parser.add_argument('-p', '--pcap', default='dump.pcap', help='Custom pcap-file to write to')
    # How many packets should we capture? Default: INF
    parser.add_argument('-c', '--count', type=int, default=-1, help='How many packets will be captured. When non provided, keep capturing until program closed')

    return parser

def main_capture_packets(sniff_obj) -> None:
    packets = (analyze_packet_verdict(plen, t, buf) for plen, t, buf in sniff_obj.capture())
    complexAnalysis(packets)

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
