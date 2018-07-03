from Crypto.Cipher import AES
from passlib.hash import sha512_crypt
import os
import hashlib
import base64
import sys
import socket, select


def hash(password):
	return hashlib.sha256(bytes(password, encoding= 'utf-8')).hexdigest()

def encrypt(raw_data):
	pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
	raw_data = pad(raw_data)
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(KEY, AES.MODE_CBC, iv)
	return base64.urlsafe_b64encode(iv + cipher.encrypt(raw_data))
	


def decrypt(encrypted_text):
	unpad = lambda s : s[:-ord(s[len(s) -1:])]
	encrypted_text = base64.urlsafe_b64decode(encrypted_text)
	iv = encrypted_text[:AES.block_size]
	cipher = AES.new(KEY, AES.MODE_CBC, iv)
	return unpad(cipher.decrypt(encrypted_text[AES.block_size:]))


def client():

	if len(sys.argv) != 5:
		print ('Usage: python client.py <hostname> <port> <name> <password>')
		
	
	HOST=sys.argv[1]
	PORT=int(sys.argv[2])
	NAME=sys.argv[3]
	PASSWORD=sys.argv[4]
	KEY=hash(PASSWORD)
	print("HOST", HOST)
	print("PORT", PORT)
	print("NAME", NAME)
	print("PASSWORD", PASSWORD)
	print("KEY", KEY)	
	
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
		readers, _,_= select.select(socket_list, [], [])
		#print(readers)
		for skt in readers:
			
			if skt == s:
				data = skt.recv(4096)
				
				if not data:
					print("\033[1;32;40m Disconnected from Encrat Server \n");
				else:
					data = decrypt(data)
					sys.stdout.write(data)
					sys.stdout.write("\033[1;32;40m"+"\n [Me]"+"\033[0m")
					sys.exit()
	
			else:
				
				message = sys.stdin.readline()
				message = '['+NAME+']: '+message
				message = encrypt(message)
				s.send(message)
				sys.stdout.write("\033[34m"+'\n[Me :] '+ "\033[0m"); sys.stdout.flush()
	
	
	
	
	
if __name__=="__main__":
	client()
	
	
	
	
	
	
	
	
	
	
	
	
	
