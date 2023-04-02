from time       import sleep
from queue      import Queue
from socket     import inet_ntoa
from translator import translator_get_arp_cache, translator_update_arp_cache
from helpers    import get_keep_running_val, add_colons_to_mac
from binascii   import hexlify
from dpkt       import arp

def apr_poison_detect(packet_queue : Queue, result_dict : dict):
    result_dict["ARP poison Detection"] = "ARP-attack not detected"

    while True:
        if not get_keep_running_val():
            print(f"<apr_poison_detect> function is now stopping, packets in queue: {packet_queue.qsize()} wait for the end of packet sequence processing !")

        if not packet_queue.empty():
            packet = packet_queue.get()
            if packet and "ARP" == packet['proto']:
                payload = packet["payload"]
                if arp.ARP != type(payload):
                    print("Error! Invalid type of payload data")
                    result_dict["ARP poison Detection"] = "Invalid payload data"
                    continue

                if "reply" == packet["type"]:
                    arp_cache = translator_get_arp_cache(None)
                    if (arp_cache[payload.tpa] != payload.tha and payload.tpa in arp_cache):
                        print("WARNING !!! Duplicate IP addresses in ARP-table detected")
                        result_dict["ARP poison Detection"] = \
                                    f"Duplicate IP addresses detected: {inet_ntoa(payload.tpa)} is assigned to {add_colons_to_mac(hexlify(arp_cache[payload.tha]))}"
                    translator_update_arp_cache(arp_cache)
            else:
                continue
        else:
            if not get_keep_running_val():
                break
            continue
    return