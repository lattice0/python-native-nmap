import socket as socket_

def transform_addresses_to_range(addresses):
	return [addresses]

class Nmap(object):
	def __init__(self, socket=None):
		if socket is None:
		    self.socket = socket_.socket(socket_.AF_INET, socket_.SOCK_STREAM)
		else:
		    self.socket = socket
		#self.socket.setdefaulttimeout(1)

	def scan(self, addresses=None, ports=None):
		result = []
		if not ports:
			ports = [80]
		if not isinstance(ports, list):
			ports = [ports]
		for address in transform_addresses_to_range(addresses):
			for port in ports:
				print("trying " + address + ":" + str(port))
				a = self.socket.connect((address, port))
				result.append(a)
		self.socket.close()
		return result
