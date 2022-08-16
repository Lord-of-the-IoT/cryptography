#!/bin/python3.10

import blowfish
from pyblake2 import blake2b

import getpass, os, sys, time
from blessings import Terminal

class FileEncrypter:
    def GetFileContent(self, filename: str) -> bytes:
        with open(filename, 'rb') as file:
            return file.read()

    def OverwriteFileContent(self, filename: str, content: bytes) -> bool:
        try:
            os.system(f'srm -z {filename}')
            with open(filename, 'wb') as file:
                file.write(content)
            return True
        except:
            return False

    def ShredFile(self, filename: str) -> bool:
        os.system(f'srm -v {filename}')

    def Encrypt(self, message : bytes, key=False, statusBar=False) -> bytes:
        if statusBar: percent = (os.get_terminal_size().columns-20)//100
        pad_size = 8 - len(message) % 8 # finds how much padding blowfish needs for valid blocks
        if statusBar: print('\t\033[1;37m'+'|'*percent*5,end='')
        message = message + bytes(pad_size for _ in range(pad_size)) # adds PKCS padding, with last byte as amount of padding
        if statusBar: print('|'*percent*5,end='')
        if key==False:
            key = getpass.getpass('Encryption key>')
        key = blake2b(key.encode()).digest() # uses blake2 to get a hash of the password to form the key
        IV = key[-8:] #first and last 8 bits of key
        key = key[:56] # gets the first 56 bytes of the key- blowfish uses 56 byte key
        if statusBar: print('|'*percent*15,end='')
        byte_order = sys.byteorder #gets the byte order --- blank if big
        if byte_order != 'little': byte_order = 'big' # sets byte_order to either little or big
        if statusBar: print('|'*percent*2,end='')
        Blowfish = blowfish.Cipher(key, byte_order=byte_order) #creates BlowFish object with correct-endian byte order
        if statusBar: print('|'*percent*20,end='')
        digest = b''.join(Blowfish.encrypt_cbc(message, IV)) #encrypts message with cbc mode
        if statusBar: print('|'*percent*53,end='\033[0m')
        return digest

    def Decrypt(self, digest: bytes, key=False, statusBar=False) -> bytes:
        if statusBar: percent = (os.get_terminal_size().columns-20)//100
        if not key:
            key = getpass.getpass('Encryption Key>')
        key = blake2b(key.encode()).digest() # uses blake2 to get a hash of the password to form the key
        if statusBar: print('\t\033[1;37m'+'|'*percent*10,end='')
        IV = key[-8:] #first and last 8 bits of key
        key = key[:56] # gets the first 56 bytes of the key- blowfish uses 56 byte key
        if statusBar: print('|'*percent*10,end='')
        byte_order = sys.byteorder #gets the byte order --- blank if big
        if byte_order != 'little': byte_order = 'big' # sets byte_order to either little or big
        if statusBar: print('|'*percent*5,end='')
        Blowfish = blowfish.Cipher(key, byte_order=byte_order) #creates BlowFish object with correct-endian byte order
        if statusBar: print('|'*percent*25,end='')
        digest = b''.join(Blowfish.decrypt_cbc(digest, IV)) #decrypts message with ecb mode
        if statusBar: print('|'*percent*50,end='')
        digest = digest[:-int(digest[-1])] #gets the size of the padding and removes the padding
        return digest

class UI:
    def __init__(self):
        self.encrypter = FileEncrypter()
        self.name = 'Advanced File Security Program'
        self.error = '\033[1;31mINVALID OPTION\033[0m'
        self.terminal = Terminal
        while True:
            try:
                self.MainPage()
            except KeyboardInterrupt:
                pass

    def MainPage(self):
        self.show_head(self.name)
        print('\n\n\toptions:\n\t[1] encrypt file\n\t[2] decrypt file\n\t[3] shred file')
        option = input('\n\t>').strip()
        if option not in '123':
            print(self.error)
            time.sleep(3)
            return
        if option == '1':
            content, filename = self.choose_file('encryption')
            while content==False: content, filename = self.choose_file('encryption')
            self.encrypt(content, filename)
            #if not self.encrypt(content, filename): self.encrypt(content, filename)
        elif option == '2':
            content, filename = self.choose_file('decryption')
            while content==False: content, filename = self.choose_file('decryption')
            if not self.decrypt(content, filename): self.decrypt(content, filename)
              
    def choose_file(self, option):
        self.show_head(f'Option: {option}')
        print('\n\n\tfiles:', end='')
        terminal_width  = os.get_terminal_size().columns
        num_spaces = terminal_width - 25 - len(os.getcwd())
        print(f'{" "*num_spaces}cwd: {os.getcwd()}')
        files = ['..']+os.listdir()
        i=0
        for filename in files: #displays files
            i+=1
            if os.path.isdir(filename): print(f'\t[{i}] \033[31m{filename}\033[0m')
            else: print(f'\t[{i}] {filename}')
        print('\n\tenter file number to select file or directory, or ctrl+c to cancel')
        option = input(f'\t>').strip()
        if option.isdigit(): option = files[int(option)-1]
        if os.path.isdir(option): #changing directory
            os.chdir(option)
            return False, False
        elif os.path.isfile(f'{os.getcwd()}/{option}'):
            content = self.encrypter.GetFileContent(filename)
            return content, filename
        else:
            print(self.error)
            time.sleep(2)
            return False, False

    def encrypt(self, content, filename):
        self.show_head('Option: encryption')
        password = getpass.getpass('\n\n\tPassword for encryption>')
        if input('\tBegin encryption? Y/N\n\t  >').lower().strip() != 'y':
            self.show_error('\tEncryption cancelled')
            time.sleep(2)
            return True
        print('\n\tStatus:')
        digest = self.encrypter.Encrypt(content, password, True)
        print('\tcontent Encrypted!\n')
        if input('\tOverwrite file with encrypted content? this process is irreversible without the key Y/N\n\t  >').lower().strip() != 'y':
            self.show_error('\tFile overwrite cancelled')
            time.sleep(2)
            return True
        self.encrypter.OverwriteFileContent(filename, digest)
        print('\tFile Overwrote!')
        time.sleep(2)
        return True

    def decrypt(self, content, filename):
        password = getpass.getpass('\n\n\tPassword for decryption>')
        if input('\tBegin decryption? Y/N\n\t  >').lower().strip() != 'y':
            self.show_error('\tDecryption cancelled')
            time.sleep(2)
            return True
        print('\n\tStatus:')
        try:
            message = self.encrypter.Decrypt(content, password, True)
        except ValueError:
            self.show_error('File not encrypted')
            time.sleep(2)
            return True
        print('\tcontent Decrypted!\n')
        self.encrypter.OverwriteFileContent(filename, message)
        print('\nFile Overwrote!')
        time.sleep(2)
        return True
    
    def shred(self, filename):
    def show_head(self, head):
        os.system('clear')
        terminal_width  = os.get_terminal_size().columns
        num_spaces = (terminal_width-len(head))//2
        print(' '*num_spaces+'\033[1m'+head+'\033[0m')

    def show_error(self, string: str, exit=False, errnum=None):
        print(f'\033[1;31m{string}\033[0m')
        if exit: sys.exit(errnum)
UI()
f = FileEncrypter()

print(f.GetFileContent('assets/exit.png'))
