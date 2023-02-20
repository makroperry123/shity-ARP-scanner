# -*- coding: utf-8 -*-
"""
Created on Mon Feb 20 15:07:10 2023

@author: alpar
"""

import socket 
import re
import sys
from colorama import init, Fore
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
import pyfiglet


def ipformat(target):
    match = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",target)
    
    if bool(match):
            print("ip format is True")
            return True
    else:
        print("ip format is False")
        
def portformat(portrange):
    
    match = re.match("([0-9]+)-([0-9]+)", portrange)
    if bool(match):
        print("port format is correct")
        minimumport,maximumport = re.split("-",portrange)
        return [minimumport,maximumport]
    else:
        print("port format is incorrect")
        return False
    
def IsPortOpen(target,port):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        socket.setdefaulttimeout(1)
        try:
            s.connect((target,port))
        except:
            return False
        else:
            return True
        
def portscan(host,ports):
    
    init()
    
    GREEN = Fore.GREEN
    RESET = Fore.RESET
    
    print("scanning for open ports ...")
    with ThreadPoolExecutor(len(ports)) as executor:
        
        results = executor.map(IsPortOpen,[host]*len(ports),ports)
        
        for port,is_open in zip(ports,results):
            if is_open:
                print(f"{GREEN}[+]{host} : port {port} open {RESET}")
                
def banner():
    ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
    print(ascii_banner)


def total_scan(ports,targetIp):
        if targetIp=="q":
            return None
        
        #host = "151.101.1.69"
        # ipformat(targetIp)    
        # print("please enter range of port number: [minimum port range]-[maximum port range]")
        # portrange = input()
        
        
        # minimumPort,maximumPort=portformat(portrange)
        # ports =[i for i in range(int(minimumPort),int(maximumPort)+1)]
        
        portscan(targetIp,ports)





