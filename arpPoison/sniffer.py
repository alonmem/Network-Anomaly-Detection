import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

i = 10
while(True):
    a = sniff(count=100000, iface = "enp0s25")
    wrpcap("Packets/pcap/sniffed{}.pcap".format(str(i)),a)   # save as pcap file
    i+=1
