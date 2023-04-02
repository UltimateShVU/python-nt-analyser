from translator_defs    import MAX_PACK_PER_SECOND_IP, MAX_PACK_PER_SECOND_ALL 
from helpers            import get_keep_running_val

def dos_detection(packet_queue, result_dict):    # Simple DoS-attack detection
    time_connections = []
    danger_adresses = {}
    last_time = 0
    
    while True:
        if not get_keep_running_val():
            print(f"<DoS detection> function is now stopping, packets in queue: {packet_queue.qsize()} wait for the end of packet sequence processing !")
        if not packet_queue.empty():
            packet = packet_queue.get()
            if packet:
                if packet['proto'] == 'Unknown' or packet['proto'] == 'ARP':
                    continue
                src = packet['IP_DATA'][0]
                time = packet['time']
                
                time_connections.append(src)
                
                if time > last_time:
                    p_overall = 0
                    p_per_ip = {}
                    for ip in set(time_connections):
                        c = time_connections.count(ip)
                        p_overall += c
                        p_per_ip[ip] = c
                    dos_flag = False
                    for ip in p_per_ip.keys():
                        if p_per_ip[ip] > MAX_PACK_PER_SECOND_IP:
                            dos_flag = True
                            print(f"WARNING! Probable DoS-attack detected from {ip} with {p_per_ip[ip]} packets per second")
                            danger_adresses[ip] = danger_adresses.setdefault(ip, 0) + p_per_ip[ip]
                    if not dos_flag and p_overall > MAX_PACK_PER_SECOND_ALL:
                        print("WARNING! Probable DDoS-attack detected")
                    last_time = time 
                    time_connections = []   
                
        elif not get_keep_running_val():
            result_data = "Following IP's were marked as probably DoS :" if len(danger_adresses) else "No dangerous IP's were detected"
            for i in danger_adresses.keys():
                result_data += f"\n {i}      with {danger_adresses[i]} sent packets"
            result_dict["DoS Detection"] = result_data
            break
