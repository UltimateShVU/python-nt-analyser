from threading      import Thread
from queue          import Queue
from helpers        import get_keep_running_val, stop_analysis

from DoS_detection  import dos_detection

def countPackets(packet_queue, result_dict):        # Example function
    j = 0

    while True:
        if not get_keep_running_val():
            print(f"<countPackets> function is now stopping, packets in queue: {packet_queue.qsize()} wait for the end of packet sequence processing !")
        if not packet_queue.empty():
            packet = packet_queue.get()
            if packet:
                j += 1
        elif not get_keep_running_val():
            result_dict["Counting packets"] = "Packets accepted: " + str(j)
            break
    return

def complexAnalysis(packets):
    analysis_funcs = [countPackets, dos_detection, ] # Add your Cool Complex Analysis Functions here
    queues = []
    resulting_data = {}
    func_threads = []

    for _ in analysis_funcs:          # Initialising queues and threads
        queues.append(Queue())

    for i in range(0, len(analysis_funcs)):
        func_threads.append(Thread(target=analysis_funcs[i], args=(queues[i], resulting_data)))

    for thread in func_threads:       # Start threads
        thread.start()

    for packet in packets:
        if not get_keep_running_val():          # Stop all threads and print results
            break
        if packet:
            for q in queues:          # Fill queues
                a = packet.copy()
                q.put(a)
        
    stop_analysis()               # When we sent all packets we need, wait until modules finish analysis
    for thread in func_threads:
        thread.join()
    print("\nResulting data from analysis modules: ")
    for data in resulting_data:
        print("\n", data, "   :   ", resulting_data.get(data))
    return
