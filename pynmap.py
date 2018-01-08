#Lucas Zanella

import socket as socket_
import ipaddress
from threading import Thread
import time

#Maximum threads concurrently running is default_delay*default_timeout
default_delay = 0.01 #Delay between thread launches
default_timeout = 3 #Timeout for each thread


def return_range_of_ips(ips):
  return [str(x) for x in list(ipaddress.ip_network(ips))]

def scan_(socket, address, port, result):
	c = socket.connect_ex((address, port))
	result[address + ":" + str(port)] = c

class Nmap(object):
	def __init__(self, socket=None, default_timeout=3):
		if socket is None:
		    self.socket = socket_.socket(socket_.AF_INET, socket_.SOCK_STREAM)
		else:
		    self.socket = socket
		self.socket.settimeout(timeout)

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
				t = Thread(target=scan_, args=(self.socket, address, port, result,))
				t.start()
				threads.append(t)
				time.sleep(default_delay)
		for thread in threads:
			thread.join()#Waits for all threads to stop so we return all results
		self.socket.close()
		return result
