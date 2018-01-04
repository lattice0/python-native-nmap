import socket

class Nmap:
	def __init__(self, socket):
		if socket is None:
		    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		else:
		    self.socket = socket
		self.socket.setdefaulttimeout(1)

	def scan(self, address=None, port=80):
		if address and port:
			result = self.socket_obj.connect((address, port))
			socket_obj.close()
		else:
			pass #throw error
