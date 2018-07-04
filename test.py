from Crypto import Random
from Crypto.Cipher import AES
from passlib.hash import sha512_crypt
import os
import hashlib
import base64
import sys
import socket, select
from Crypto.Hash import SHA256

def hash(password):
	return hashlib.sha256(bytes(password, encoding= 'utf-8')).digest()
	#return SHA256.new(password.encode()).digest()



def encrypt(raw_data):
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CFB, iv)
	ciphertext = cipher.encrypt(raw_data.encode("utf-8"))
	return (ciphertext, iv)
	


def decrypt(encrypted_text):
	unpad = lambda s : s[:-ord(s[len(s) -1:])]
	encrypted_text = base64.urlsafe_b64decode(encrypted_text)
	iv = encrypted_text[:AES.block_size]
	cipher = AES.new(KEY, AES.MODE_CBC, iv)
	return unpad(cipher.decrypt(encrypted_text[AES.block_size:]))






password="mypassword"

key = hash(password)
print(len(key))

#encrypt("some data to encrypt") #error when calling this function

