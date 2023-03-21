from pylibpcap.base import Sniff

def getSniffObj(iface, output_file="pcap.pcap") -> object:
    return Sniff(iface, count=-1, promisc=1, out_file=output_file)
    
def printPayloads(plen, t, buf):
    print("[+]: Payload len=", plen)
    print("[+]: Time", t)
    print("[+]: Payload", buf.decode('utf-8'))    
