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
	return sha256_crypt.encrypt(password)
	


	

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]




def broadcast_message(server_socket,socket, message):
	#broadcast message to everyone
	for s in socket_list:
		if s is not server_socket and s is not socket:
			socket.send(message.encode())





config=configparser.ConfigParser()
config.read('config.ini')

HOST=config['details']['HOST']
PORT=int(config['details']['PORT'])
PASSWORD=config['details']['PASSWORD']
KEY=hash(PASSWORD)
socket_list=[]

'''
def encrypt(raw_data):
	return raw_data
	#raw_data = pad(raw_data)
	#iv = Random.new().read(AES.block_size)
	#cipher = AES.new(KEY, AES.MODE_CBC, iv)
	#return base64.b64encode( iv + cipher.encrypt( raw_data ) )
	


def decrypt(encrypted_text):
	return raw_data


'''

def encrypt(secret,data):
	BLOCK_SIZE = 32
	PADDING = '{'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	cipher = AES.new(secret)
	encoded = EncodeAES(cipher, data)
	return encoded

def decrypt(secret,data):
	BLOCK_SIZE = 32
	PADDING = '{'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	cipher = AES.new(secret)
	decoded = DecodeAES(cipher, data)
	return decoded

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
				
				broadcast_message(server_socket, conn_socket, encrypt(KEY,"(%s,%s) entered chat room\n" % address))
			else:
				try:
					data = s.recv(4096)
					data = decrypt(data)
				
					if data:
						broadcast_message(server_socket, s, data)
					
					else:
						if socket in socket_list:
							socket_list.remove(s)
							broadcast_message(server_socket, s, encrypt(KEY,"user (%s, %s) went offline\n" % address))
					
				except:
					broadcast_message(server_socket, s, encrypt(KEY,"User (%s, %s) is offline\n" % address))
					continue
	server_socket.close()


if __name__=="__main__":
	server()




