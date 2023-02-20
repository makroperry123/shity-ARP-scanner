# -*- coding: utf-8 -*-
"""
Created on Sun Feb 19 22:40:22 2023

@author: alpar
"""

from scapy.all import Ether,ARP,conf,srp
import sys

sys.path.insert(0,"C:\\Users\hp\\Desktop\\projeler\\arp scanner\\mis")
from port_scan import *

from datetime import datetime
from win_nic import NetworkAdapters

this_pc_nics = NetworkAdapters()
ethernet_nic = this_pc_nics.get_nic(index = 10)


INTERFACE =ethernet_nic.description

def ARP_Scan(ips):
    banner()
    print("please enter range of port you want to search in your network: [minimum port range]-[maximum port range]")
    portrange = input()
    
    minimumPort,maximumPort=portformat(portrange)
    ports =[i for i in range(int(minimumPort),int(maximumPort)+1)]
    
    print("[*] Scanning...") 
    start_time = datetime.now()
    conf.verb = 0 
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout = 2, iface = INTERFACE,inter = 0.1) 
    
    for snd,rcv in ans:
        print ("\n[*] IP - MAC")
        print(rcv.sprintf(r"%ARP.psrc% - %Ether.src%"))
        total_scan(ports,rcv.sprintf(r"%ARP.psrc%"))
        
        
    stop_time = datetime.now()
    total_time = stop_time - start_time 
    print("\n[*] Scan Complete. Duration:", total_time)
    
    
    
if __name__ == "__main__":
    ARP_Scan(sys.argv[1])