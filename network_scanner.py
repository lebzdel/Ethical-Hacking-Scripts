#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options_b = parser.parse_args()

    return options_b


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_result(result_list):
    print()
    print(" " + "-" * 40)
    print(" IP\t\t\tAt MAC address")
    print(" " + "-" * 40)
    for element in result_list:
        print(" " + element["ip"] + "\t\t" + element["mac"])
    print()


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
