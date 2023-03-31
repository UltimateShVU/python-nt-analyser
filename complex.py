from threading      import Thread
from queue          import Queue
keep_running = 1

def stop_analysis():
    global keep_running
    keep_running = 0

def countPackets(packet_queue, result_dict):
    i = 0
    j = 0
    while True:
        global keep_running                           
        if not keep_running:
            print("Count Packets function is now stopping, packets in queue: ", packet_queue.qsize())
        if not packet_queue.empty():
            packet = packet_queue.get()
            if packet:
                j += 1
        elif not keep_running:
            result_dict["Counting packets"] = "Packets accepted: "+str(j)
            return

def complexAnalysis(packets):
    analysis_funcs = [countPackets, ] #add your Cool Complex Analysis Functions here
    queues = []
    resulting_data = {}
    func_threads = []
    for func in analysis_funcs:     #Initialising queues and threads
        queues.append(Queue())
       
    for i in range(0, len(analysis_funcs)):
        func_threads.append(Thread(target=analysis_funcs[i], args=(queues[i], resulting_data)))
        
    for thread in func_threads:     #Start threads
        thread.start()
    
    for packet in packets:
        if not keep_running:        #Stop all threads and print results

            for thread in func_threads:
                thread.join()
            for data in resulting_data:
                print(data, "   :   ", resulting_data.get(data))
            return
        if packet:    
            for q in queues:        #Fill queues
                a = packet.copy()
                q.put(a)
