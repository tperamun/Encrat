import sys, socket, select
import os
import hashlib
import os
import configparser
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2










#def hash(password):
#	return hashlib.sha256(bytes(password, encoding= 'utf-8')).digest()
	

def make_key(password, salt=None):
	if salt is None:
		salt = Random.new().read(8)
	
	key = PBKDF2(password, salt, AES.block_size, 10000)
	return (key, salt)



def broadcast_message(server_socket,sock, message):
	#broadcast message to everyone
	for s in socket_list:
		if s != server_socket and s != sock:
			try:
				socket.send(message)
			except:
				s.close()
				if s in socket_list:
					socket_list.remove(s)

def encrypt(raw_data, KEY):
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(KEY, AES.MODE_CFB, iv)
	ciphertext = cipher.encrypt(raw_data.encode("utf-8"))
	return (ciphertext, iv)
	


def decrypt(encrypted_text,KEY,iv):
	cipher = AES.new(KEY, AES.MODE_CFB, iv)
	msg = cipher.decrypt(encrypted_text).decode("utf-8")
	return msg
	
config=configparser.ConfigParser()
config.read('config.ini')

HOST=config['details']['HOST']
PORT=int(config['details']['PORT'])
PASSWORD=config['details']['PASSWORD']
socket_list=[]



def server():

	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #TCP Connection
	server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	server_socket.bind((HOST, PORT))
	server_socket.listen(10)
	
	
	socket_list.append(server_socket)
	
	print("Server started on port "+ str(PORT))
	
	while True:
		
		readers,_,_= select.select(socket_list,[],[],0) #timeout_value=0 never blocks
		
		for s in readers:
			
			if s==server_socket:
				conn_socket, address = server_socket.accept()
				socket_list.append(conn_socket)
				print ("user (%s, %s) connected" % address)
				PASSWORD=config['details']['PASSWORD']
				KEY, SALT =make_key(PASSWORD)
				ciphertext, iv = encrypt("(%s,%s) entered chat room\n" % address, KEY)
				ciphertext  = SALT + ciphertext + iv
				broadcast_message(server_socket, conn_socket, ciphertext)
			else:
				try:
					data = s.recv(4096)
					
					salt = data[0:8]
					iv = data[-16:]
					data= data[8:]
					data=data[:-16]
					KEY, _ = make_key(PASSWORD,salt)

					data = decrypt(ciphertext, KEY, iv)
					if data:

						broadcast_message(server_socket, s, data)
					
					else:
						if s in socket_list:
							socket_list.remove(s)
							PASSWORD=config['details']['PASSWORD']
							KEY, SALT =make_key(PASSWORD)
							
							ciphertext, iv = encrypt("user (%s, %s) went offline\n" % address, KEY)
							print("ciphertext lulu", len(ciphertext)) 
							ciphertext  = SALT + ciphertext + iv
							broadcast_message(server_socket, s, ciphertext)
					
				except:
					PASSWORD=config['details']['PASSWORD']
					KEY, SALT =make_key(PASSWORD)
					message, iv= encrypt("user (%s, %s) is offline\n" % address, KEY)
					message = SALT + message + iv
					broadcast_message(server_socket, s, message)
					continue

	server_socket.close()






if __name__=="__main__":
	sys.exit(server())




