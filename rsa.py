#!/bin/python3.10
import os, rsa

class RSA:
    def __init__(self):
        self.getKeys()

    def getKeys(self):
        if os.path.exists('keys/RSApubkey.pem') and os.path.exists('keys/RSAprivkey.pem'):
            #load keys
            with open('keys/RSApubkey.pem', 'rb') as p:
                self.publicKey = rsa.PublicKey.load_pkcs1(p.read())
            with open('keys/RSAprivkey.pem', 'rb') as p:
                self.privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        else:
            if not os.path.exists('keys'): os.mkdir('keys')
            #generate keys
            (self.publicKey, self.privateKey) = rsa.newkeys(1024)
            #save keys for future date
            with open('keys/RSApubkey.pem', 'wb') as file:
                file.write(self.publicKey.save_pkcs1('PEM'))
            with open('keys/RSAprivkey.pem', 'wb') as file:
                file.write(self.privateKey.save_pkcs1('PEM'))

    def encrypt(self, digest : str) -> bytes:
        #encrypts the given string digest with the public key and then returns bytes
        return rsa.encrypt(digest.encode('ascii'), self.publicKey)
    
    def decrypt(self, digest: bytes):
        #decrypts the given bytes digest with the private key and then returns string or false
        try: return rsa.decrypt(digest, self.privateKey).decode('ascii')
        except: return False

    def sign(self, digest: str):
        #proves that the message is real
        return rsa.sign(digest.encode('ascii'), self.privateKey, 'SHA-1')

    def verify(self, digest, signature):
        #checks that the signature is valid
        #parameters: digest-- the decrypted result
        #            signature-- the signature
        try:return rsa.verify(digest.encode('ascii'), signature, self.publicKey) == 'SHA-1'
        except: return False
