from threading      import Thread
from queue          import Queue
keep_running = 1

def stop_analysis():
    global keep_running
    keep_running = 0
    print("Signal gone")

def countPackets(packet_queue, result_dict):
#Protofunction, used for demonstration
#Counts number of all pacets or dict packets
    i = 0
    j = 0
    while True:
        print("In count_packets True_cycle")
        global keep_running                           
        if not keep_running:
            print("Not keep_running, queue size: ", packet_queue.qsize())
        print("want get queue")
        if not packet_queue.empty():
            packet = packet_queue.get()
            print("got queue")
            i += 1
            if packet:
                j += 1
                print(packet["verdict"], "|", packet["time"], "|", packet["payload"], "|", packet["description"], "|")
        elif not keep_running:
            print("Gonna return stuff from counPackets")
            result_dict["Counting packets"] = "Packets accepted: "+str(i)+"  ;   "+"Not 'None' packets accepted: "+str(j)
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
            print("Not keep running in complexAnaysis")

            for thread in func_threads:
                thread.join()
            for data in resulting_data:
                print(data, "   :   "resulting_data.get(data))
            return
        if packet:    
            for q in queues:        #Fill queues
                a = packet.copy()
                #print(a)
                q.put(a)
