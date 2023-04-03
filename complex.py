from threading      import Thread
from queue          import Queue
from helpers        import get_keep_running_val, stop_analysis

from analysis_functions.DoS_detection          import dos_detection
from analysis_functions.arp_poison_detection   import arp_poison_detect
from analysis_functions.dns_spoofing_detection import dns_spoof_detect

# Example function
def countPackets(packet_queue, result_dict):
    counter = 0

    while True:
        if not get_keep_running_val():
            print(f"<countPackets> function is now stopping, packets in queue: {packet_queue.qsize()} wait for the end of packet sequence processing !")
        if not packet_queue.empty():
            packet = packet_queue.get()
            if packet:
                counter += 1
        elif not get_keep_running_val():
            result_dict["Counting packets"] = "Packets accepted: " + str(counter)
            break
    return

def packet_sequence_info(result: dict):
    print()
    for data in result:
        print(data, "   :   ", result.get(data))


def complexAnalysis(packets):
    # add your complex analysis functions here
    analysis_funcs = [countPackets, dos_detection, arp_poison_detect, dns_spoof_detect, ]
    queues = list()
    resulting_data = dict()
    func_threads = list()

    # Initialising queues and threads
    for _ in analysis_funcs:
        queues.append(Queue())

    for i in range(0, len(analysis_funcs)):
        func_threads.append(Thread(target=analysis_funcs[i], args=(queues[i], resulting_data)))

    # Start threads
    for thread in func_threads:
        thread.start()

    # Filling queues
    for packet in packets:
        if not get_keep_running_val():
            break
        if packet:
            for queue in queues:
                queue.put(packet.copy())

    # When we sent all packets we need, wait until modules finish analysis
    stop_analysis()
    print("\n[MIDDLE] Interim summary of captured traffic:")
    packet_sequence_info(resulting_data)
    for thread in func_threads:
        thread.join()

    print("\n[FINISH] Resulting data from analysis modules: ")
    packet_sequence_info(resulting_data)

    return
