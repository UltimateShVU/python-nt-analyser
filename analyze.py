import dpkt
import ipaddress

def bytes2ip(bytestring):
    return str(ipaddress.IPv4Address(bytestring))

def getFriendlyPacket(plen, t, buf):
    print("Raw packet: \n", buf)
    print("\n\n\n")
    eth = dpkt.ethernet.Ethernet(buf)
    print("Dpkt eth: \n", eth)
    print("\n\n\n")
    ip = eth.data
    print("Dkpt ip: \n", ip)
    print("\n\n\n")
    packet_info = {'src_ip'  : bytes2ip(ip.src),
                   'dst_ip'  : bytes2ip(ip.dst),
                   'payload' : ip.data
    }
#    ip = eth.data
#    tcp = ip.data
#    return tcp
    return packet_info


