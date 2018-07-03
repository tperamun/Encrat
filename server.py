import sys, socket, select
import os
import hashlib
import os
import configparser
from passlib.hash import sha256_crypt
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random

def hash(password):
	return hashlib.sha256(bytes(password, encoding= 'utf-8')).hexdigest()
	


	

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]




def broadcast_message(server_socket,socket, message):
	#broadcast message to everyone
	for s in socket_list:
		if s is not server_socket and s is not socket:
			socket.send(message)





config=configparser.ConfigParser()
config.read('config.ini')

HOST=config['details']['HOST']
PORT=int(config['details']['PORT'])
PASSWORD=config['details']['PASSWORD']
KEY=hash(PASSWORD)
socket_list=[]


def encrypt(raw_data):
	pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
	raw_data = pad(raw_data)
	iv = Random.new().read(AES.block_size)
	print("iv", sys.getsizeof(iv))
	print("KEY", sys.getsizeof(KEY))
	cipher = AES.new(KEY, AES.MODE_CBC, iv)
	return base64.urlsafe_b64encode(iv + cipher.encrypt(raw_data))
	


def decrypt(encrypted_text):
	unpad = lambda s : s[:-ord(s[len(s) -1:])]
	encrypted_text = base64.urlsafe_b64decode(encrypted_text)
	iv = encrypted_text[:AES.block_size]
	sys.getsizeof(iv)
	cipher = AES.new(KEY, AES.MODE_CBC, iv)
	return unpad(cipher.decrypt(encrypted_text[AES.block_size:]))
	



def server():

	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #TCP Connection
	server_socket.bind((HOST, PORT))
	server_socket.listen(5)
	
	
	socket_list.append(server_socket)
	
	print("Server started on port "+ str(PORT))
	
	while True:
		
		readers,_,_= select.select(socket_list,[],[],0) #timeout_value=0 never blocks
		
		for s in readers:
			
			if s==server_socket:
				#when a client first connects
				conn_socket, address = server_socket.accept()
				socket_list.append(conn_socket)
				
				broadcast_message(server_socket, conn_socket, encrypt("(%s,%s) entered chat room\n" % address))
			else:
				try:
					data = s.recv(4096)
					data = decrypt(data)
				
					if data:
						broadcast_message(server_socket, s, data)
					
					else:
						if socket in socket_list:
							socket_list.remove(s)
							broadcast_message(server_socket, s, encrypt("user (%s, %s) went offline\n" % address))
					
				except:
					broadcast_message(server_socket, s, encrypt("User (%s, %s) is offline\n" % address))
					continue
	server_socket.close()


if __name__=="__main__":
	server()




