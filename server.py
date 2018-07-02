import sys, socket, select
import os
import hashlib
import os
import configparser
from passlib.hash import sha512_crypt

def hash(password):
	return sha512_crypt.encrypt(password)
	


config=configparser.ConfigParser()
config.read('config.ini')

HOST=config['details']['HOST']
PORT=config['details']['PORT']
PASSWORD=config['details']['PASSWORD']
KEY=hash(PASSWORD)

socket_list=[]


def server():

	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #TCP Connection
	server_socket.bind((HOST, PORT))
	server_socket.listen(5)
	
	
	socket_list.append(server_socket)
	
	print("Server started on port "+ str(PORT))
	
	while True:
		
		readers,_,_= select.select(socket_list,[],[],0) #timeout_value=0 never blocks
		
		for socket in readers:
			
			if socket==server_socket:
				connection, address = server_socket.accept()








