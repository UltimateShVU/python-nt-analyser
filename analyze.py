import dpkt
from analyze_defs import *
from helpers      import bytes2ip

# Autor: Pavel Chernov
# @brief: Analyze and mark traffic. 
# @description: After analysis, the package is marked.
#               According to this marking, you can put forward a recommendation
#               for attention to the sender of this traffic.

### TEST: use hping3 for tcp, udp, icmp testing

analyze_black_list = dict()
analyze_white_list = dict()

def analyze_return_negative_answer(flag: int, desc: str, payload: str) -> dict:
    if (flag == ANALYZE_VERDICT_NORMAL): 
        return None

    if flag == ANALYZE_VERDICT_INVALID:
        flag = "invalid"
    elif flag == ANALYZE_VERDICT_WARN:
        flag = "warning"
    return \
    {
        "verdict": flag,
        "description": desc,
        "payload": payload
    }

### Analyze UDP-traffic module

def analyze_UDP_packet(ip_packet: dpkt.ip.IP, tcp_packet: dpkt.udp.UDP) -> dict:
    pass

### Analyze ICMP-traffic module

def analyze_ICMP_packet(ip_packet: dpkt.ip.IP, tcp_packet: dpkt.icmp.ICMP) -> dict:
    pass

### Analyze TCP-traffic module

def analyze_check_flags_tcp(tcp_flags: int) -> int:
    if tcp_flags:
        return ANALYZE_VERDICT_NORMAL
    else:
        return ANALYZE_VERDICT_INVALID

def analyze_TCP_packet(ip_packet: dpkt.ip.IP, tcp_packet: dpkt.tcp.TCP) -> dict:
    src_ip_addr   = bytes2ip(ip_packet.src)
    src_ip_port   = tcp_packet.sport

    dst_ip_addr   = bytes2ip(ip_packet.dst)
    dst_ip_port   = tcp_packet.dport
    payload = f"{src_ip_addr}:{src_ip_port} -> {dst_ip_addr}:{dst_ip_port}"

    check1 = analyze_check_flags_tcp(tcp_packet.flags)

    if (check1 != ANALYZE_VERDICT_NORMAL):
        try:
            analyze_black_list[f"[TCP] {src_ip_addr}"] += 1
        except KeyError:
            analyze_black_list[f"[TCP] {src_ip_addr}"]  = 0

        return analyze_return_negative_answer(ANALYZE_VERDICT_INVALID, \
                                              "Invalid packet's flags",\
                                              f"[TCP] {payload}")
    
    ### SSH connection checking
    # internal IP-addresses - unexpected as default
    if (dst_ip_port == SSH_PORT or dst_ip_port == SSH_PORT_ADDON):
        try:
            analyze_black_list[f"[SSH] {src_ip_addr}"] += 1
        except KeyError:
            analyze_black_list[f"[SSH] {src_ip_addr}"] = 0

        if analyze_black_list[f"[SSH] {src_ip_addr}"] > SSH_NEW_CONN_PCTS:
            return analyze_return_negative_answer(ANALYZE_VERDICT_WARN,                 \
                                                    "Unexpected SSH-connection occured",\
                                                    f"[SSH] {payload}")
    ### Next checking

    return None


### Driver
def analyze_packet_verdict(plen, t, buf) -> dict:
    ethernet_layer = dpkt.ethernet.Ethernet(buf)
    ### TODO: предусмотреть ETH_TYPE_ARP для проверки на ARP-спуфинг
    if (type(ethernet_layer.data) != dpkt.ip.IP): return None

    packet_verdict = dict()
    ip_layer   = ethernet_layer.data
    next_layer = ip_layer.data

    if (type(next_layer) == dpkt.udp.UDP):
        packet_verdict = analyze_UDP_packet(ip_layer, next_layer)

    if (type(next_layer) == dpkt.tcp.TCP):
        packet_verdict = analyze_TCP_packet(ip_layer, next_layer)

    if (type(next_layer) == dpkt.icmp.ICMP):
        packet_verdict = analyze_ICMP_packet(ip_layer, next_layer)

    if packet_verdict:
        packet_verdict.update({"time": t})

    return packet_verdict
