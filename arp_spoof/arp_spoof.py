#! /usr/bin/env python3

import scapy.all as scapy

packet = scapy.ARP(op=2, pdst="10.0.2.18")