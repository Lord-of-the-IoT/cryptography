import twofish, secret

class TwoFish:
    def __init__(self):
        self.getKey()
    
    def getKey(self):
        if os.path.exists('keys/TwoFishkey.pem'):
            with open('keys/TwoFishkey.pem', 'rb') as file:
                self.key=file.read()
        else:
            if not os.path.exists('keys'): os.mkdir('keys')
            self.key=secrets.token_bytes()
            with open('keys/TwoFishkey.pem', 'wb') as file:
                file.write(self.key)

    def encrypt(self, message):
        block_size=16 #the block size is 16 bytes
        if len(message)%16: #if the length of the message is not a multiple of the block size
            message=str(message+chr(1)*(block_size-len(message)%16)) #uses chr(1) as padding
        message=message.encode('ascii')
        TwofishDeamon=twofish.Twofish(self.key) #creates a twofish instance
        digest=bytes()
        for i in range(int(len(message)/block_size)):
            digest+=TwofishDeamon.encrypt(message[i*block_size:(i+1)*block_size])
        return digest

    def decrypt(self, digest):
        block_size=16 #the block size is 16 bytes
        TwofishDeamon=twofish.Twofish(self.key) #creates a twofish instance
        message=str()
        for i in range(int(len(digest)/block_size)):
            message+=TwofishDeamon.decrypt(digest[i*block_size:(i+1)*block_size]).decode('ascii') #decrypts the message
        for i in range(len(message)):
            if message[::-1][i] != chr(1): message=message[:(len(message)-i)]; break #removes the padding
        return message
