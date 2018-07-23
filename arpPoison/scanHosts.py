import os
import time
import fnmatch
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy import all as scapy

d = {}

def generateList(d):
    while True:
        os.system("nmap -sP -PS22,3389 192.168.1.* > namp.txt")

        nmapRet = open("namp.txt", "r")
        spoofed = open("HostsSpoofed.txt", "w")
        c = False
        
        for line in nmapRet.readlines():
            if "Nmap scan report for" in line and not c:
                IP = line[-13:].strip()
                if IP == "192.168.1.1":
                    continue
                c=True
            if "MAC" in line and c:
                MAC = line[13:31].strip()    
                d[IP] = MAC
                c=False
            
        for i in d:
            spoofed.write(i + "\n")

        spoofed.close()
        nmapRet.close()
        
        time.sleep(300) # 5 minutes
