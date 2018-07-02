import sys, socket, select
import os
import hashlib
import os
import configparser
from passlib.hash import sha512_crypt
from Crypto.Cipher import AES
from Crypto import Random

def hash(password):
	return sha512_crypt.encrypt(password)
	

def broadcast_message(server_socket,socket, message):
	#broadcast message to everyone
	for s in socket_list:
		if s is not server_socket and s is not socket:
			socket.send(message)
	
	
def pad(text):
	return text + (AES.block_size - len(AES.block_size) % AES.block_size * chr(AES.block_size - len(text) % AES.block_size))
	

def unpad(text):
	return text[:-ord(text[len(text)-1:])]






config=configparser.ConfigParser()
config.read('config.ini')

HOST=config['details']['HOST']
PORT=int(config['details']['PORT'])
PASSWORD=config['details']['PASSWORD']
KEY=hash(PASSWORD)
socket_list=[]

def encrypt(raw_data):
	raw_data=pad(raw_data)
	IV= Random.new().read(AES.block_size)
	cipher= AES.new(KEY, AES.MODE_CBC, IV)
	return base64.b64encode(IV + cipher.encrypt(raw_data))


def decrypt(encrypted_text):
	encrypted_text=base64.b64decode(encrypted_text) 
	IV= cipher[:AES.block_size]
	cipher = AES.new(KEY, AES.MODE_CBC, IV)
	return unpad(cipher.decrypt(encrypted_text[AES.block_size:])).decode()



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


if __name__=="__main__":
	server()




