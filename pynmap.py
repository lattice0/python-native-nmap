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
	
def ip_header(source, destination, version=5, protocol=None, id=None):
	ip_ihl = 5 # Internet Header Length; Length of entire IP header.???
	ip_ver = 4 # Version no. of Internet Protocol used (e.g. IPv4).
	ip_tos = 0 # DSCP: Differentiated Services Code Point; this is Type of Service.
	ip_tot_len = 0  # kernel will fill the correct total length
	ip_id = id   # Identification: If IP packet is fragmented during the transmission, all the fragments contain same identification number. to identify original IP packet they belong to.
	ip_frag_off = 0 # Fragment Offset: This offset tells the exact position of the fragment in the original IP Packet.
	ip_ttl = 255 # Time to Live: To avoid looping in the network, every packet is sent with some TTL value set, which tells the network how many routers (hops) this packet can cross. At each hop, its value is decremented by one and when the value reaches zero, the packet is discarded.
	ip_proto = socket.IPPROTO_TCP if protocol=="TCP" or socket.IPROTO_UDP if protocol=="UDP"
	ip_check = 0    # kernel will fill the correct checksum
	ip_saddr = socket.inet_aton(source)   #Spoof the source ip address if you want to
	ip_daddr = socket.inet_aton(destination)
	
	ip_ihl_ver = (version << 4) + ihl
	
	# the ! in the pack format string means network order
	ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
	return ip_header

def tcp_header(source=None, destination=None, sequence=None, ack_sequence=None, data_offset=None, window=None, checksum=0):
	# tcp header fields
	tcp_source = source   #source port
	tcp_dest = destination   #destination port
	tcp_seq = sequence #(32 bits) specifies the number assigned to the first byte of data in the current message. 
	tcp_ack_seq = ack_sequence #(32 bits) contains the value of the next sequence number that the sender of the segment is expecting to receive, if the ACK control bit is set.
	tcp_doff = data_offset    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
	#tcp flags
	tcp_fin = 0 #Means that the sender of the flag has finished sending data.
	tcp_syn = 1 #Synchronizes sequence numbers to initiate a connection.
	tcp_rst = 0 #Resets the connection.
	tcp_psh = 0 #Indicates that data should be passed to the application as soon as possible.
	tcp_ack = 0 #Indicates that acknowledgement number is valid.
	tcp_urg = 0 #Indicates that some urgent data has been placed
	tcp_window = socket.htons (window)    #(16 bits) specifies the size of the sender's receive window (that is, buffer space available for incoming data).
	tcp_check = checksum #(16 bits) indicates whether the header was damaged in transit.
	tcp_urg_ptr = 0 # (16 bits) points to the first urgent data byte in the packet.
	
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
