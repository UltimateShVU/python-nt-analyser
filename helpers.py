import ipaddress
import dpkt

keep_running = 1
def get_keep_running_val() -> int:
    return keep_running

def stop_analysis():
    global keep_running
    keep_running = 0

def __bytes2ip(bytestring):
    return str(ipaddress.IPv4Address(bytestring))

# For TCP/UDP traffic
def helpers_get_ip_data(ip_packet: dpkt.ip.IP, packet) -> tuple:
    src_ip_addr = __bytes2ip(ip_packet.src)
    dst_ip_addr = __bytes2ip(ip_packet.dst)

    if type(packet) != dpkt.icmp.ICMP:
        src_ip_port = packet.sport
        dst_ip_port = packet.dport

        return (src_ip_addr, src_ip_port, dst_ip_addr, dst_ip_port)
    else:
        return (src_ip_addr, dst_ip_addr)

# This function accepts a 12 hex digit
# string and converts it to a colon separated string
def add_colons_to_mac(mac_addr : bytes):
    s = []
    for i in range(6):
        tmp = i*2
        s.append(mac_addr[tmp:tmp+2])

    r = b":".join(s)
    return r
