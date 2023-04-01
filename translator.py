import dpkt
from   socket   import inet_ntoa
from   binascii import hexlify
from   translator_defs import *
from   helpers         import helpers_get_ip_data, add_colons_to_mac

"""
    @autor: Pavel Chernov (K1rch)
    @brief: Translate input traffic and return valid serialized packet
"""

# Для удобности вынес в другой файл. После того,
# как вынесешь функционал по анализу в другое место, удали файл analyze.py вместе с этим комментом

### Analyze ARP-traffic module
arp_cache   = dict()

def translator_get_arp_cache() -> dict:
    return arp_cache

def __translate_ARP_packet(eth_packet: dpkt.ethernet.Ethernet) -> dict:
    global arp_cache
    packet_data = {"proto": "ARP"}
    arp_packet  = eth_packet.arp

    if (1 == arp_packet.op):
        packet_data.update({"type": "request"})
    elif (2 == arp_packet.op):
        packet_data.update({"type": "reply"})
    else:
        raise Exception("OCCURED UNEXPECTED VALUE OF OPERATION CODE")

    packet_data.update({"From": add_colons_to_mac(hexlify(eth_packet.src)), \
                        "To": add_colons_to_mac(hexlify(eth_packet.dst))})

    # Проверка на отравление ARP-таблицы. Вынести функционал ниже в отдельный поток.
    """
        if (2 == arp_packet.op):
            if (arp_cache[arp_packet.tpa] != arp_packet.tha and arp_packet.tpa in arp_cache):
                raise Exception(f"Duplicate IP addresses detected: {inet_ntoa(arp_packet.tpa)} is assigned to {add_colons_to_mac(hexlify(arp_cache[arp_packet.tha]))}")
            arp_cache[arp_packet.tpa] = arp_packet.tha
    """
    ### Flags inside payload in ALL packet_data
    packet_data.update({"payload": arp_packet})

    return packet_data



### Analyze ICMP-traffic module

def __translate_ICMP_packet(ip_packet: dpkt.ip.IP, icmp_packet: dpkt.icmp.ICMP) -> dict:
    packet_data = dict()
    # ip_addr_data[0] - src_ip; ip_addr_data[2] - dst_ip
    ip_addr_data = helpers_get_ip_data(ip_packet, icmp_packet)
    packet_data.update({"proto": "ICMP", "IP_DATA": ip_addr_data, "payload": icmp_packet.data})

    return packet_data


### Analyze UDP-traffic module

def __translate_TFTP_packet(ip_packet: dpkt.tftp.TFTP, packet_data: dict) -> dict:
    packet_data.update({"proto": "TFTP", "filename": ip_packet.filename, "mode": ip_packet.mode})
    return packet_data

def __translate_UDP_packet(ip_packet: dpkt.ip.IP, udp_packet: dpkt.udp.UDP) -> dict:
    packet_data = dict()

    # ip_addr_data[0] - src_ip; ip_addr_data[1] - src_port,
    # ip_addr_data[2] - dst_ip, ip_addr_data[3] - dst_port
    ip_addr_data = helpers_get_ip_data(ip_packet, udp_packet)
    dst_port = ip_addr_data[-1]

    packet_data.update({"proto" : "UDP", "IP_DATA" : ip_addr_data})

    if (dst_port == DNS_PORT):
        try:
            dns_request = dpkt.dns.DNS(udp_packet.data)
        except Exception:
            pass
        else:
            packet_data.update({"proto" : "DNS"})
            packet_data.update({"request": dns_request})

    elif (dst_port == TFTP_PORT):
        try:
            tftp_request = dpkt.tftp.TFTP(udp_packet.data)
        except Exception:
            pass
        else:
            packet_data = __translate_TFTP_packet(tftp_request, packet_data)

    if packet_data["proto"] == "UDP":
        packet_data.update({"payload": udp_packet})

    return packet_data

### Analyze TCP-traffic module
def __translate_http_header_tcp(http_header: dpkt.http.Request, packet_data: dict) -> dict:
    packet_data.update({"proto" : "HTTP", "URI" : http_header.uri, "method" : http_header.method})
    return packet_data
 
def __translate_TCP_packet(ip_packet: dpkt.ip.IP, tcp_packet: dpkt.tcp.TCP) -> dict:
    packet_data = dict()

    # ip_addr_data[0] - src_ip; ip_addr_data[1] - src_port,
    # ip_addr_data[2] - dst_ip, ip_addr_data[3] - dst_port
    ip_addr_data = helpers_get_ip_data(ip_packet, tcp_packet)
    dst_ip_port = ip_addr_data[-1]

    packet_data.update({"proto" : "TCP", "IP_DATA": ip_addr_data})

    if dst_ip_port == SSH_PORT or dst_ip_port == SSH_PORT_ADDON:
        packet_data.update({"proto" : "SSH"})

    elif dst_ip_port == HTTP_PORT and len(tcp_packet.data):
        try:
            http_request = dpkt.http.Request(tcp_packet.data)
        except Exception:
            pass
        else:
            packet_data = __translate_http_header_tcp(http_request, packet_data)


    elif (dst_ip_port == FTP_PORT or dst_ip_port == FTP_PORT_ADDON):
        packet_data.update({"proto": "FTP"})

    elif (dst_ip_port == TELNET_PORT):
        packet_data.update({"proto" : "TELNET"})

    if packet_data["proto"] == "TCP":
        packet_data.update({"payload": tcp_packet})

    return packet_data

### Driver
def translate_packet(plen, t, buf) -> dict:
    packet_data    = dict()
    ethernet_layer = dpkt.ethernet.Ethernet(buf)
    packet_type    = ethernet_layer.type

    try:
        if packet_type == dpkt.ethernet.ETH_TYPE_IP:

            ip_layer   = ethernet_layer.data
            next_layer = ip_layer.data

            if type(next_layer) == dpkt.udp.UDP:
                packet_data = __translate_UDP_packet(ip_layer, next_layer)

            if type(next_layer) == dpkt.tcp.TCP:
                packet_data = __translate_TCP_packet(ip_layer, next_layer)

            if type(next_layer) == dpkt.icmp.ICMP:
                packet_data = __translate_ICMP_packet(ip_layer, next_layer)

        elif packet_type == dpkt.ethernet.ETH_TYPE_ARP:
            packet_data = __translate_ARP_packet(ethernet_layer)


        else:
            packet_data.update({"proto": "Unknown"})

    except Exception as E:
        print(f"Exception occured: {E} !")

    if packet_data:
        packet_data.update({"time": t})

    print(packet_data)
    return packet_data