from queue      import Queue
from helpers    import get_keep_running_val
import                 dpkt

def dns_spoof_detect(packet_queue : Queue, result_dict : dict):
    result_dict["DNS spoof detect"] = "DNS-spoofing attack not detected"

    while True:
        if not get_keep_running_val():
            print(f"<dns_spoof_detect> function is now stopping, packets in queue: {packet_queue.qsize()} wait for the end of packet sequence processing !")

        if not packet_queue.empty():
            packet = packet_queue.get()
            if packet and "DNS" == packet["proto"]:
                dns_request = packet["request"]
                if dpkt.dns.DNS != type(dns_request):
                    print("Error! Invalid type of DNS-request", type(dns_request))
                    continue

                if dns_request.qr != dpkt.dns.DNS_Q or \
                   dns_request.opcode != dpkt.dns.DNS_QUERY or \
                   len(dns_request.qd) != 1 or len(dns_request.an) != 0 or \
                   len(dns_request.ns) != 0 or \
                   dns_request.qd[0].cls != dpkt.dns.DNS_IN or \
                   dns_request.qd[0].type != dpkt.dns.DNS_A:
                    continue

                # insert your domain's name here
                if dns_request.qd[0].name != "nstu.ru":
                    continue

                source_ip, destination_ip = packet["IP_DATA"][0], packet["IP_DATA"][2]
                print("WARNING !!! DNS-spoofing attack detected")
                result_dict.update({"DNS spoof detect": f"{source_ip} -> {destination_ip} detect DNS-Spoofing attack"})
            else:
                continue
        else:
            if not get_keep_running_val():
                break
            continue

    return