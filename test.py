from pynmap import *

nmap = Nmap()
r = nmap.scan(addresses="192.168.1.2", ports=80)
print(r)
