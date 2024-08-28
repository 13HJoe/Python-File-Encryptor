import sys
import os
import glob
import hashlib
import maskpass
from termcolor import colored
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
# ---------------------------------------------------------#
if sys.argv[1] == "-h" or sys.argv[1] == "-help":
    print("Syntax - 'cryptF -e unencrypted.txt  key'\n")
    print("       - 'cryptF -d encrypted.txt  key decryptedFile' \n")
    print("=> key : length = 16 [The length of the key must only be 16 characters]")
    exit(0)
#---------------------------------------------------------#
if len(sys.argv) <= 1:
    print("Invalid Usage")
    print("Use <cryptF -h OR -help> for information")
    exit(0)
#----------------------------------------------------------#
flag = sys.argv[1]
if flag != "-e" and flag != "-d":
    print("Invalid Usage")
    print("Use <cryptF -h OR -help> for information")
    exit(0)
# ---------------------------------------------------------#
filename = sys.argv[2]
list_check_file = glob.glob(filename)
if len(list_check_file) == 0:
    cwd1 = os.getcwdb()
    print(colored("File not found","light_red"),colored("in the directory ->","light_red"),colored(cwd1.decode('utf-8'),"light_red"))
    exit(0)
#----------------------------------------------------------#
key = maskpass.askpass(prompt="Key:", mask="*")
if len(key) != 16:
    print(colored("Invalid Key Length\n=> key : length = 16 [The length of the 16 must only be 16 characters]","light_red"))
    exit(0)                                                                                                   
key = key.encode("utf-8")  # Encode key to binary data
# ---------------------------------------------------------#
# Encryption Flag
if flag == "-e":
    with open(filename, "rb") as file:  #'rb' opens file; -Read-Binary mode
        data = file.read()
    del_option = input(colored("Delete Unencrypted File? Y/N \n ->","light_red"))
    if del_option == "Y":
        os.remove(filename)  # remove sensitive unencrypted file
    hash = hashlib.sha256(key).hexdigest() #key is already encoded to utf-8s     # Hash Key and store to new text file
    key_hash_filename = filename[:-4] + "keyHash.txt"
    with open(key_hash_filename,'w') as key_hash_file:
        key_hash_file.write(hash)
    # Instance of Cipher
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    # Write Ciphertext(binary format) to binary file
    newfile = sys.argv[2] + ".bin"
    with open(newfile, "wb") as file:
        file.write(ciphertext)
    print(colored("Encrypted Data -> ","light_green"), newfile)
# ---------------------------------------------------------#
# Decryption Flag
elif flag == "-d":
    key_hash_filename = filename[:-8]+"keyHash.txt"
    with open(key_hash_filename,'r') as key_hash_file:
        hash = key_hash_file.read().encode('utf-8')
        currentInputHash = hashlib.sha256(key).hexdigest()
        if(hash!=currentInputHash.encode('utf-8')):
            print(colored("Wrong Key","red"))
            sys.exit(0)
        else:
            print(colored("Correct Key","light_green"))
    os.remove(key_hash_filename)
    with open(filename,"rb") as file:
        ciphertext = file.read()
    decipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = decipher.decrypt(ciphertext)
    decrypted_data = unpad(decrypted_data, AES.block_size)
    endIndex = len(filename)
    newfile = filename[0 : endIndex - 4]
    with open(newfile, "wb") as file:  #'wb' opens file; Write-Binary mode
        file.write(decrypted_data)
    print(colored("Decrypted Data -> ","light_green"), newfile)
    # OPTION - Delete Source File
    option = input(colored("Delete Encrypted File? Y/N \n->","light_red"))
    if option == "Y":
        os.remove(filename)
        print(colored("File removed successfully","light_green"))
        #print(colored("Be sure to remove padded data","light_yellow"))
