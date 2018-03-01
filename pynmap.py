#Lucas Zanella

import socket as socket
import ipaddress
from threading import Thread
import time
import copy
import socks
from struct import *

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
	
def ip_header(version=5, protocol=None):
	source_ip = '192.168.1.101'
	dest_ip = '192.168.1.1' # or socket.gethostbyname('www.google.com')
	
	# ip header fields
	ip_ihl = 5
	ip_ver = 4
	ip_tos = 0
	ip_tot_len = 0  # kernel will fill the correct total length
	ip_id = 54321   #Id of this packet
	ip_frag_off = 0
	ip_ttl = 255
	ip_proto = socket.IPPROTO_TCP if protocol=="TCP" or socket.IPROTO_UDP if protocol=="UDP"
	ip_check = 0    # kernel will fill the correct checksum
	ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
	ip_daddr = socket.inet_aton ( dest_ip )
	
	ip_ihl_ver = (version << 4) + ihl
	
	# the ! in the pack format string means network order
	ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

def tcp_header(source=0, destination=0, sequence=0, size=0):
	# tcp header fields
	tcp_source = 1234   # source port
	tcp_dest = 80   # destination port
	tcp_seq = 454
	tcp_ack_seq = 0
	tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
	#tcp flags
	tcp_fin = 0
	tcp_syn = 1
	tcp_rst = 0
	tcp_psh = 0
	tcp_ack = 0
	tcp_urg = 0
	tcp_window = socket.htons (5840)    #   maximum allowed window size
	tcp_check = 0
	tcp_urg_ptr = 0
	
	tcp_offset_res = (tcp_doff << 4) + 0
	tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
	
	# the ! in the pack format string means network order
	tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff)
    s = s + (s >> 16)
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s

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
	def new_raw_socket(self):
	        if not self.proxy:
	                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
	        else:
	                #print("using socks " + self.proxy['socks_host'] + ":" + str(self.proxy['socks_port']))
	                #s = socks.socksocket()
	                #s.set_proxy(socks.SOCKS5, self.proxy['socks_host'], self.proxy['socks_port'])
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
