#!/usr/bin/env python

import scapy.all as scapy
import argparse
import subprocess
import re

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Here is the address of the subnet that you're gonna scan")


    options = parser.parse_args()
    print(options)

    return options.target


def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #scapy.ls(scapy.Ether())

    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

    ### Parsing with the help of RegEx
    # print(answered_list.summary())
    # print(str(answered_list[0][1].summary()))
    # ip_mac_comb = re.search(r'(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w) says (\d*\.\d*\.\d*\.\d*)', str(answered_list[0][1].summary()))
    #
    # print("[+] From IP: " + ip_mac_comb.group(2) + " is MAC: " + ip_mac_comb.group(1))
def print_result(results_lists):
    print("IP\t\t\tMAC Address\n-------------------------------------------------------------------------------------")

    for client in results_lists:
        print(client["ip"] + "\t\t" + client["mac"])


scan_result = scan(get_arguments())
print_result(scan_result)
