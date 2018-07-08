import socket
import configparser
from _thread import * 
import sys

num_threads=0

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

config = configparser.ConfigParser()
config.read('config.ini')

HOST = config['details']['HOST']
PORT= int(config['details']['PORT'])

server_socket.bind((HOST, PORT))

clients=[]

server_socket.listen(10)





def client_thread(client_socket):
	global num_threads
	num_threads+=1

	client_socket.send("Encrat Chat Room\n".encode())
	
	while True:
		data = client_socket.recv(1024)
		#reply = data.decode()
		
		if not data:
			break
		
		for client in clients:
			if client  != client_socket:
				client.send(data)			

	connection.close()



while True:
	client_socket , address = server_socket.accept()
	clients.append(client_socket)
	print("User (%s, %s) connected\n" % address)
	start_new_thread(client_thread, (client_socket, ))

	#print("I should never get here")
	while num_threads > 0:
		pass





server_socket.close()

