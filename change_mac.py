#!/usr/bin/env python

import subprocess
import re

new_address = "00:11:22:33:44:66"

subprocess.call("ifconfig eth0 down", shell=True)
subprocess.call("ifconfig eth0 hw ether " + new_address, shell=True)
subprocess.call("ifconfig eth0 up", shell=True)

ifconfig_result = str(subprocess.check_output(["ifconfig", "eth0"]))

mac_address = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)

if not mac_address:
    print("[-] Could not read MAC address.")
else:
    mac_address = mac_address.group(0)

    if new_address == mac_address:
        print("[+] MAC address was successfully changed.")
    else:
        print("[-] MAC address was not changed.")
