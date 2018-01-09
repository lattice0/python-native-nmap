#Lucas Zanella

import socket as socket
import ipaddress
from threading import Thread
import time
import copy
import socks

#Maximum threads concurrently running is default_delay*default_timeout
default_delay = 0.01 #Delay between thread launches
default_timeout = 3 #Timeout for each thread

def return_range_of_ips(ips):
  return [str(x) for x in list(ipaddress.ip_network(ips))]

def scan_(socket, address, port, result):
        try:
	        c = socket.connect_ex((address, port))
	        result[address + ":" + str(port)] = c
        except socks.GeneralProxyError as e:
                print(e)
        except Exception as e:
                pass
        socket.close()
	


class Nmap(object):
	def __init__(self, proxy=None, default_timeout=3):
		self.proxy = proxy
		self.default_timeout = default_timeout
		
	def new_socket(self):
	        if not self.proxy:
	                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	        else:
	                #print("using socks " + self.proxy['socks_host'] + ":" + str(self.proxy['socks_port']))
	                s = socks.socksocket()
	                s.set_proxy(socks.SOCKS5, self.proxy['socks_host'], self.proxy['socks_port'])
	                #s.connect(('192.168.25.1', 80))
	        s.settimeout(self.default_timeout) 
	        return s

	def scan(self, addresses=None, ports=None):
		result = {}
		threads = []
		if not ports:
			ports = [80]
		if not isinstance(ports, list):
			ports = [ports]
		for address in return_range_of_ips(addresses):
			for port in ports:
				#print("trying " + address + ":" + str(port))
				t = Thread(target=scan_, args=(self.new_socket(), address, port, result,))
				t.start()
				threads.append(t)
				time.sleep(default_delay)
		for thread in threads:
			thread.join()#Waits for all threads to stop so we return all results
		return result
