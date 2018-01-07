#Lucas Zanella

import socket as socket_
import ipaddress
from threading import Thread
import time

delay = 0.01

def return_range_of_ips(ips):
  return [str(x) for x in list(ipaddress.ip_network(ips))]

class Nmap(object):
	def __init__(self, socket=None, timeout=3):
		if socket is None:
		    self.socket = socket_.socket(socket_.AF_INET, socket_.SOCK_STREAM)
		else:
		    self.socket = socket
		self.socket.settimeout(timeout)
	
	def scan_(self, address, port, result):
		c = self.socket.connect_ex((address, port))
		results.append(c)

	def scan(self, addresses=None, ports=None):
		result = {}
		threads = []
		if not ports:
			ports = [80]
		if not isinstance(ports, list):
			ports = [ports]
		for address in return_range_of_ips(addresses):
			for port in ports:
				print("trying " + address + ":" + str(port))
				t = Thread(target=scan_, args=(address, port, result,))
			    	t.start()
				time.sleep(delay)
		for thread in threads:
			thread.join()
		self.socket.close()
		return result
