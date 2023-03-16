import dpkt
import ipaddress

def bytes2ip(bytestring):
    return str(ipaddress.IPv4Address(bytestring))

def getFriendlyPacket(buf):
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    packet_info = {'sip' : bytes2ip(ip.src),
                   'dip' : bytes2ip(ip.dst),
                   'data' : ip.data
    }
#    ip = eth.data
#    tcp = ip.data
#    return tcp
    return packet_info


