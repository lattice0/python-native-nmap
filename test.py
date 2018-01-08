#!/usr/bin/env python3
#Lucas Zanella

from pynmap import *

nmap = Nmap()
r = nmap.scan(addresses="192.168.1.2/24", ports=80)
print(r)
