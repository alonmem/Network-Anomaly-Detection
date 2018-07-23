import csv
import time
import pandas as pd
import numpy as np
from sklearn.preprocessing import normalize

protocols_dict = dict()
services_dict = dict()


def get_label(packet):
    if int(packet[-1]) == 0:
        return 0
    return 1


def filter_packet(packet):
    global protocols_dict
    filtered_packet = packet.copy()
    filtered_packet.pop() #label
    filtered_packet.pop() # attack type
    filtered_packet.pop(5) # protocol state
    
    srcIP = filtered_packet[0].split('.')
    dstIP = filtered_packet[2].split('.')
    proto = filtered_packet[4]
    service = filtered_packet[12]
    dstPort = packet[3]
    srcPort = packet[1]

    filtered_packet.pop(0) # source IP
    filtered_packet.pop(1) # destination IP
    filtered_packet.pop(2) # Protocol
    filtered_packet.pop(9) # Service

    filtered_packet = srcIP + filtered_packet
    filtered_packet1 = filtered_packet[:5] + dstIP + filtered_packet[5:]

    if proto not in protocols_dict:
        protocols_dict[proto] = len(protocols_dict)
        
    filtered_packet1.insert(10, protocols_dict[proto])
    
    if service not in services_dict:
        services_dict[service] = len(services_dict)
        
    filtered_packet1.insert(10, services_dict[service])

    if srcPort == '-':
        srcPort = -1
    if dstPort == '-':
        dstPort = -1
    for i in range(len(filtered_packet1)):
        if filtered_packet1[i] == '' or filtered_packet1[i] == ' ':
            filtered_packet1[i] = -1
    
    try:
        int(srcPort)
    except:
        srcPort = int(srcPort, 16)
    filtered_packet1[4] = srcPort
    
    try:
        int(dstPort)
    except:
        dstPort = int(dstPort, 16)
    filtered_packet1[9] = dstPort
        
    final_packet = [float(i) for i in filtered_packet1]
    del final_packet[33:35] # start&end time

    return final_packet

def split(arr, size):
    arrs = []
    while len(arr) > size:
        arrs.append(arr[:size])
        arr = arr[size:]
    #arrs.append(arr) without the last timeseries (not size 100)
    return arrs

def create_training_set(packets, sequence_length):
    start = time.time()
    print("normalizing data...")
    print(np.array(packets).shape)
    packets = normalize(np.array(packets, dtype = np.float64)) #here
    print("normalization time: ", int(time.time()-start))
    print("spliting data...")
    result = split(packets, sequence_length)
    print("split time: ", int(time.time()-start))
    print("converting to nparray...")
    result = np.array(result)
    print("conversion time: ", int(time.time()-start))
    
    print("set shape:", result.shape)
    print()
    return result


def get_good_bad_data(path, sequence_length):
    start = time.time()

    all_csv_data = []
    packets_for_training = []
    packets_for_testing = []

    print("reading file..")
    with open(path, mode='r', encoding='utf-8-sig') as f:

        reader = csv.reader(f)
        all_csv_data = list(reader)
        print("reading time:", int(time.time()- start), "seconds")
        print()

        start = time.time()
        for pkt in all_csv_data:
            if get_label(pkt) == 1:
                vector = filter_packet(pkt)
                packets_for_testing.append(vector)
            else:
                vector = filter_packet(pkt)
                packets_for_training.append(vector)

    good = create_training_set(packets_for_training, sequence_length)
    bad = create_training_set(packets_for_testing, sequence_length)
    return good, bad


def get_all_data(path, sequence_length):
    start = time.time()
    all_csv_data = []
    packets_to_return = []
    infos = [] # packets labeled 1 in every timestep

    print("reading data...")
    with open(path, mode='r', encoding='utf-8-sig') as f:
        reader = csv.reader(f)
        all_csv_data = list(reader)
        print("reading time: ", int(time.time()- start))
        print()

        start = time.time()
        for pkt in all_csv_data:
            vector = filter_packet(pkt)
            if len(vector) != 50:
                continue
            packets_to_return.append(vector)
            infos.append(get_label(pkt))

    data_return = create_training_set(packets_to_return, sequence_length)
    infos = split(infos, sequence_length)
    info = np.array([sum(i) for i in infos])
    return data_return, info
