import sys
from pylibpcap      import get_iface_list, get_first_iface
from pylibpcap.base import Sniff
from analyze        import *
from sniff          import *
from main_defs      import *

def main_arg_parser_banner() -> None:
    print("Please, choice the interface for scanning packets:")
    print("+--- LIST ---+")
    print("\n".join(get_iface_list()))
    print("+------------+")
        
def main_loop(sniff_obj):
    for plen, t, buf in sniff_obj.capture():
        packet = getFriendlyPacket(plen, t, buf)
        print(t, packet)

def start() -> None:
    ### TODO:
    # 1) make a `banner` with help-message
    # 2) make a help `flag` 
    input_length = len(sys.argv)

    if MAIN_INTERFACE_FLAG in sys.argv:
        if input_length < MAIN_AVERAGE_PARAMS:
            main_arg_parser_banner()
        elif input_length == MAIN_AVERAGE_PARAMS:
            sniff_obj = getSniffObj(sys.argv[MAIN_AVERAGE_PARAMS-1])
            main_loop(sniff_obj)
        ### TODO:
        # 1) make a another flag-endpoints 

    else:
        # by default? this functionality really needed?
        sniff_obj = getSniffObj(get_first_iface())
        main_loop(sniff_obj)

        stats = sniff_obj.stats()
        print(stats.capture_cnt, " packets captured")
        print(stats.ps_recv,     " packets received by filter")
        print(stats.ps_drop,     " packets dropped by kernel")
        print(stats.ps_ifdrop,   " packets dropped by iface")

if __name__ == '__main__':
    start()
