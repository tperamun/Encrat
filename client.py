import socket
import configparser
#### server address temporary
config = configparser.ConfigParser()
config.read('config.ini')

HOST = config['details']['HOST']
PORT= config['details']['PORT']
#####


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = (HOST, PORT)
print("Connecting to {} port {}".format(*server_address))

sock.connect(server_address)



try:
	message = b'Thi





s.connect(server_address)

msg = s.recv(1024)

s.close()

print(msg.decode('ascii'))


