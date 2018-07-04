from Crypto.Cipher import AES
from passlib.hash import sha512_crypt
import os
import hashlib
import base64
import sys
import socket, select
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2



def make_key(password, salt=None):
	if salt is None:
		salt = Random.new().read(8)
	
	key = PBKDF2(password, salt, AES.block_size, 10000)
	return (key, salt)


def encrypt(raw_data, KEY):
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(KEY, AES.MODE_CFB, iv)
	ciphertext = cipher.encrypt(raw_data.encode("utf-8"))
	return (ciphertext, iv)
	


def decrypt(encrypted_text,KEY,iv):
	cipher = AES.new(KEY, AES.MODE_CFB, iv)
	msg = cipher.decrypt(encrypted_text).decode("utf-8")
	return msg
	


def client():



	
	if len(sys.argv) != 5:
		print ('Usage: python client.py <hostname> <port> <name> <password>')
		sys.exit()
	
	HOST=sys.argv[1]
	PORT=int(sys.argv[2])
	NAME=sys.argv[3]
	PASSWORD=sys.argv[4]
	
#	print("HOST", HOST)
#	print("PORT", PORT)
#	print("NAME", NAME)
#	print("PASSWORD", PASSWORD)
#	print("KEY", KEY)	
	
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(2)

	try:
		s.connect((HOST, PORT))
	except:
		print("\033[91m"+'Unable to connect'+"\033[0m")
		sys.exit()
	
	print("Connection established. You can start sending messages")
	sys.stdout.write("\033[34m"+'\n[Me :] '+ "\033[0m");sys.stdout.flush()
	

	
	while True:
		socket_list= [sys.stdin, s]
		readers, writers,errors= select.select(socket_list, [], [])
		#print(readers)
		for skt in readers:
			
			if skt == s:
				data = skt.recv(4096)
				print("data length", len(data))

				if not data:
					print("\033[1;32;40m Disconnected from Encrat Server \n");
					sys.exit()
				else:
					salt = data[0:8]
					iv   = data[-16:]
					data = data[8:]
					data = data[:-16]

					KEY, _ =make_key(PASSWORD, salt)
					data = decrypt(data, KEY, iv)
					sys.stdout.write(data)
					sys.stdout.write("\033[1;32;40m"+"\n [Me :]"+"\033[0m");sys.stdout.flush()
	
			else:
				
				message = sys.stdin.readline()
				message = '['+NAME+']: '+message
				key, salt = make_key(PASSWORD)
				ciphertext, iv = encrypt(message, key)
				ciphertext = salt + ciphertext + iv
				print("the cipher", ciphertext)
				s.send(ciphertext)
				sys.stdout.write("\033[34m"+'\n[Me :] '+ "\033[0m"); sys.stdout.flush()
	
	
	
	
		

if __name__ =="__main__":
	sys.exit(client())
	
	
	
	
	
	
	
	
	
	
	
	
	
