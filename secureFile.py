import sys
import hashlib
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
#---------------------------------------------------------#
#---------------------------------------------------------#
if sys.argv[1] == '-h' or sys.argv[1] == '-help':
  '''
  with open('help.txt','r') as file:
    help_data = file.read()
    print(help_data)
  '''
  print("Syntax - 'file.py -e unencrypted.txt  key'\n")
  print("       - 'file.py -d encrypted.txt  key decryptedFile' \n") 
  print("=> key : length = 16") 
  exit(0)
#---------------------------------------------------------#
#---------------------------------------------------------#

keyString = sys.argv[3] #Extract key from the command line
key = keyString.encode('utf-8') #Encode key to binary data

#---------------------------------------------------------#
#---------------------------------------------------------#
#Encryption Flag
if(sys.argv[1]=="-e"):
  filename = sys.argv[2]
  with open(filename, 'rb') as file: #'rb' opens file; -Read-Binary mode
    data = file.read()
  #os.remove(filename) #remove sensitive unencrypted file
  #Instance of Cipher
  cipher = AES.new(key, AES.MODE_ECB)
  padded_data = pad(data, AES.block_size)
  ciphertext = cipher.encrypt(padded_data)
  #Write Ciphertext(binary format) to binary file
  with open('crptd.bin', 'wb') as file:
    file.write(ciphertext)
  print("Encrypted Data -> crptd.bin")

#---------------------------------------------------------#
#---------------------------------------------------------#
#Decryption Flag
else:
  filename = sys.argv[2]
  with open(filename, 'rb') as file:
    ciphertext = file.read()
  decipher = AES.new(key, AES.MODE_ECB)
  decrypted_data = decipher.decrypt(ciphertext)
  with open("out.txt", 'wb') as file: #'wb' opens file; Write-Binary mode
    file.write(decrypted_data)
  print("Decrypted Data -> out.txt")
  #OPTION - Delete Source File
  option = input("Delete Original File? Y/N \n->")
  if option == 'Y':
    os.remove(filename)
    print("File removed successfully")
