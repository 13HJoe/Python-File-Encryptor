import random

class InvalidKeyLengthError(Exception):
    def __init__(self):
        self.message = "Invalid Key Length \nAES128 key length must be 16 bytes only"
        Exception.__init__(self, self.message)

class AES:
    def __init__(self):
        self.s_box_string = '63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76' \
                            'ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0' \
                            'b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15' \
                            '04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75' \
                            '09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84' \
                            '53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf' \
                            'd0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8' \
                            '51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2' \
                            'cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73' \
                            '60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db' \
                            'e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79' \
                            'e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08' \
                            'ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a' \
                            '70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e' \
                            'e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df' \
                            '8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16'
        
        self.s_box_string = self.s_box_string.replace(" ","")
        self.s_box = bytearray.fromhex(self.s_box_string)

    def bytes_from_state(self, state: list[list[int]]) -> bytes:
        ret_bytes = bytes(state[0] + state[1] + state[2] + state[3])
        return ret_bytes
        

    def state_from_bytes(self, data: bytes) -> list[list[int]]:
        state = [data[i*4:(i+1)*4] for i in range(len(data) // 4)]
        return state

    def sub_word(self, word: list[int]) -> list[int]:
        substituted_word = bytes(self.s_box[i] for i in word)
        return substituted_word
    
    def rot_word(self, word: list) -> list:
        word = word[1:] + word[-1]
        return word
    

    def xor_bytes(self, a: bytes, b: bytes) -> bytes:
        return bytes([x ^ y for x,y in zip(a, b)])


    # round constant
    def rcon(i: int) -> bytes:
         rcon_lookup = bytearray.fromhex("01020408102040801B36")
         rcon_value = bytes(rcon_lookup[i-1], 0, 0 ,0)
         return rcon_value
    


    def key_expansion(self, key: bytes, nr:int, nb: int = 4) -> list[list[list[4]]]:

        w = self.state_from_bytes(key)

        nk = len(key) // 4 # 128 - 32

        for i in range(nk, nb * (nr + 1)):
            temp = w[i-1]
            if i % nk == 0:
                temp = self.xor_bytes(self.sub_word(self.rot_word(temp)), self.rcon(i // nk))
            elif nk > 6 and i % nk == 4:
                temp = self.sub_word(temp)
            word_i = self.xor_bytes(w[i-nk], temp)
            w.append(word_i)

        return [w[i*4:(i+1)*4] for i in range(len(w // 4))]

    #-----------------------------------------------------------------------------#
    def add_round_key(self, state:list[list[int]], key_schedule: list[list[int]], round: int):
        round_key = key_schedule[round]
        
        for (a,b) in zip(state, round_key):
            for (i,j) in zip(a,b):
                i = i ^ j
        
        return state

    def sub_bytes(self, state: list[list[int]]):
        for r in range(len(state)):
            state[r] = [self.s_box[r][c] for c in range(len(state[0]))]
        
        return state

    def shift_rows(self, state: list[list[int]]):

        state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1] 
                
        state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2] 

        state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3] 


    def mix_columns(self, state):
        pass
    #------------------------------------------------------------------------------#

    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        
        state = self.state_from_bytes(None)

        num_of_rounds = -1
        if key_length == 128:
            num_of_rounds = 10
        elif key_length == 192:
            num_of_rounds = 12
        elif key_length == 256: 
            num_of_rounds = 14
        else:
            raise InvalidKeyLengthError
        


        key_schedule = self.key_expansion(key, num_of_rounds)

        self.add_round_key(state, key_schedule, round=0)
        
        key_length = len(key) * 8 # in bits

        


        for round in range(1, num_of_rounds):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, key_schedule, round)


        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, key_schedule, round=num_of_rounds)

        
        ciphertext = self.bytes_from_state(None)

        return ciphertext


if __name__ == "__main__":

    # NIST AES-128 test C1.
    plaintext = bytearray.fromhex("00112233445566778899aabbccddeeff")
    key = bytearray.fromhex("000102030405060708090a0b0c0d0e0f")
    expected_ciphertext = bytearray.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    aes_cipher = AES()
    ciphertext = aes_cipher.encrypt(plaintext, key)

    assert (ciphertext == expected_ciphertext)



    # NIST AES-192 test C2.
    plaintext = bytearray.fromhex("00112233445566778899aabbccddeeff")
    key = bytearray.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    expected_ciphertext = bytearray.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")
    aes_cipher = AES()
    ciphertext = aes_cipher.encrypt(plaintext, key)

    assert (ciphertext == expected_ciphertext)




    # NIST AES-256 test C3.
    plaintext = bytearray.fromhex("00112233445566778899aabbccddeeff")
    key = bytearray.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    expected_ciphertext = bytearray.fromhex("8ea2b7ca516745bfeafc49904b496089")
    aes_cipher = AES()
    ciphertext = aes_cipher.encrypt(plaintext, key)

    assert (ciphertext == expected_ciphertext)





'''

class InvalidKeyLengthError(Exception):
    def __init__(self):
        self.message = "Invalid Key Length \nAES128 key length must be 16 bytes only"
        Exception.__init__(self, self.message)

class AES:
    ECB = 1
    CBC = 2
    def __init__(self, key, mode):
        self.mode = mode
        if len(str(key)) != 16:
            raise InvalidKeyLengthError
        self.key =  key
        self.sbox = self.get_SBOX()
        self.inv_sbox = self.get_INVERSE_SBOX()

    def gen_rand_SBOX(self):
        sbox = []
        visited = set()
        c = 0
        for _ in range(16):
            row  = []
            for _ in range(16):
                val = random.randrange(0,256)
                while val in visited:
                    val = random.randrange(0,256)
                visited.add(val)
                if val < 16:
                    val = '0x0'+hex(val)[2]
                    row.append(val)
                else:
                    row.append(hex(val))
            sbox.append(row)
        return sbox
    def hexify_string(self, i, j):
        dir = 'abcdef'
        res = '0x'
        if i >= 10:
            res += dir[i-10]
        else:
            res += str(i)
        if j >= 10:
            res += dir[j-10]
        else:
            res += str(j)
        return res
    def gen_rand_INVERSE_SBOX(self):
        inv_sbox = [[ hex(0)  for _ in range(16)] for _ in range(16)]
        for i in range(16):
            for j in range(16):
                val = str(self.sbox[i][j])
                x = int(val[2], 16)
                y = int(val[3], 16)
                # print(val,"--",self.hexify_string(i,j),'--',i,j)
                inv_sbox[x][y] = self.hexify_string(i,j)
        return inv_sbox
    

    def get_SBOX(self):
        sbox = [
        #      0       1       2       3       4       5       6       7       8       9       a       b       c       d       e       f                     =28c=
            ['0x63', '0x0c', '0xc8', '0x83', '0xcf', '0xaf', '0x38', '0x9a', '0xbb', '0x22', '0xe9', '0xc5', '0x57', '0x0f', '0xa4', '0x04'], # 0
            ['0x18', '0xfc', '0xce', '0xf4', '0x78', '0xe8', '0xb0', '0x7b', '0x4d', '0x89', '0x12', '0xcd', '0x90', '0xf0', '0xd0', '0x31'], # 1
            ['0xc0', '0x1e', '0x8a', '0x20', '0xda', '0x9f', '0x91', '0x0a', '0x37', '0x4a', '0x73', '0xa8', '0xf2', '0xd5', '0x2a', '0xab'], # 2 
            ['0x7a', '0x54', '0x84', '0x5f', '0x69', '0x1a', '0xa1', '0xaa', '0x40', '0xc3', '0x41', '0xb9', '0x9d', '0x13', '0x6f', '0x72'], # 3
            ['0x10', '0x77', '0x6b', '0xd6', '0x7d', '0xf3', '0x93', '0xf6', '0x35', '0xdb', '0xa7', '0xdc', '0xff', '0x8f', '0x86', '0x07'], # 4
            ['0xb6', '0x7c', '0x1f', '0x61', '0x82', '0x3e', '0x27', '0xfa', '0x62', '0x97', '0x48', '0x8c', '0xe2', '0xed', '0x25', '0xd3'], # 5
            ['0x2b', '0x67', '0xac', '0x98', '0xf9', '0x11', '0x36', '0xe5', '0x06', '0xae', '0x34', '0xd8', '0xfd', '0x51', '0xf8', '0x2f'], # 6
            ['0x17', '0x2e', '0x74', '0x32', '0x59', '0x80', '0xf7', '0xc2', '0xdf', '0x01', '0x24', '0x0d', '0x33', '0x3a', '0xd9', '0xa2'], # 7 
            ['0xc1', '0x58', '0x45', '0xb8', '0x8b', '0xb4', '0x4f', '0x8e', '0xca', '0x1b', '0x6a', '0xcb', '0x05', '0x39', '0xb5', '0x29'], # 8
            ['0xe0', '0x5c', '0x5e', '0x8d', '0x6d', '0xe3', '0x3b', '0xba', '0xa5', '0x95', '0x1d', '0x68', '0xd1', '0x70', '0x6e', '0x30'], # 9
            ['0x0b', '0x4c', '0x94', '0x99', '0x3c', '0x52', '0xef', '0xbc', '0xc7', '0xa9', '0x00', '0xea', '0x92', '0xde', '0xc6', '0x14'], # a
            ['0x65', '0xcc', '0x53', '0x76', '0x9b', '0x5b', '0x79', '0x55', '0x9c', '0xad', '0xd4', '0xfe', '0x75', '0x28', '0x1c', '0x66'], # b
            ['0x46', '0x49', '0xe1', '0xd2', '0xeb', '0xbd', '0x4b', '0xb7', '0x96', '0xc9', '0xa6', '0xe7', '0x3f', '0x47', '0xee', '0x0e'], # c
            ['0x44', '0x56', '0xec', '0x5d', '0xb3', '0x50', '0x88', '0x42', '0xdd', '0x16', '0x3d', '0x2d', '0xbe', '0x6c', '0x09', '0x26'], # d
            ['0x7f', '0x4e', '0x19', '0x71', '0xd7', '0x81', '0x5a', '0x87', '0x2c', '0xa0', '0xa3', '0x23', '0xf5', '0xb2', '0x64', '0x02'], # e
            ['0x21', '0x15', '0xfb', '0x60', '0x7e', '0x85', '0xc4', '0x08', '0xf1', '0xe6', '0xbf', '0xe4', '0x43', '0x9e', '0x03', '0xb1'], # f
        ]
        return sbox
    def get_INVERSE_SBOX(self):
        inv_sbox =  [
        #      0       1       2       3       4       5       6       7       8       9       a       b       c       d       e       f
            ['0xaa', '0x79', '0xef', '0xfe', '0x0f', '0x8c', '0x68', '0x4f', '0xf7', '0xde', '0x27', '0xa0', '0x01', '0x7b', '0xcf', '0x0d'], # 0
            ['0x40', '0x65', '0x1a', '0x3d', '0xaf', '0xf1', '0xd9', '0x70', '0x10', '0xe2', '0x35', '0x89', '0xbe', '0x9a', '0x21', '0x52'], # 1
            ['0x23', '0xf0', '0x09', '0xeb', '0x7a', '0x5e', '0xdf', '0x56', '0xbd', '0x8f', '0x2e', '0x60', '0xe8', '0xdb', '0x71', '0x6f'], # 2
            ['0x9f', '0x1f', '0x73', '0x7c', '0x6a', '0x48', '0x66', '0x28', '0x06', '0x8d', '0x7d', '0x96', '0xa4', '0xda', '0x55', '0xcc'], # 3
            ['0x38', '0x3a', '0xd7', '0xfc', '0xd0', '0x82', '0xc0', '0xcd', '0x5a', '0xc1', '0x29', '0xc6', '0xa1', '0x18', '0xe1', '0x86'], # 4
            ['0xd5', '0x6d', '0xa5', '0xb2', '0x31', '0xb7', '0xd1', '0x0c', '0x81', '0x74', '0xe6', '0xb5', '0x91', '0xd3', '0x92', '0x33'], # 5
            ['0xf3', '0x53', '0x58', '0x00', '0xee', '0xb0', '0xbf', '0x61', '0x9b', '0x34', '0x8a', '0x42', '0xdd', '0x94', '0x9e', '0x3e'], # 6
            ['0x9d', '0xe3', '0x3f', '0x2a', '0x72', '0xbc', '0xb3', '0x41', '0x14', '0xb6', '0x30', '0x17', '0x51', '0x44', '0xf4', '0xe0'], # 7
            ['0x75', '0xe5', '0x54', '0x03', '0x32', '0xf5', '0x4e', '0xe7', '0xd6', '0x19', '0x22', '0x84', '0x5b', '0x93', '0x87', '0x4d'], # 8
            ['0x1c', '0x26', '0xac', '0x46', '0xa2', '0x99', '0xc8', '0x59', '0x63', '0xa3', '0x07', '0xb4', '0xb8', '0x3c', '0xfd', '0x25'], # 9
            ['0xe9', '0x36', '0x7f', '0xea', '0x0e', '0x98', '0xca', '0x4a', '0x2b', '0xa9', '0x37', '0x2f', '0x62', '0xb9', '0x69', '0x05'], # a
            ['0x16', '0xff', '0xed', '0xd4', '0x85', '0x8e', '0x50', '0xc7', '0x83', '0x3b', '0x97', '0x08', '0xa7', '0xc5', '0xdc', '0xfa'], # b
            ['0x20', '0x80', '0x77', '0x39', '0xf6', '0x0b', '0xae', '0xa8', '0x02', '0xc9', '0x88', '0x8b', '0xb1', '0x1b', '0x12', '0x04'], # c
            ['0x1e', '0x9c', '0xc3', '0x5f', '0xba', '0x2d', '0x43', '0xe4', '0x6b', '0x7e', '0x24', '0x49', '0x4b', '0xd8', '0xad', '0x78'], # d
            ['0x90', '0xc2', '0x5c', '0x95', '0xfb', '0x67', '0xf9', '0xcb', '0x15', '0x0a', '0xab', '0xc4', '0xd2', '0x5d', '0xce', '0xa6'], # e
            ['0x1d', '0xf8', '0x2c', '0x45', '0x13', '0xec', '0x47', '0x76', '0x6e', '0x64', '0x57', '0xf2', '0x11', '0x6c', '0xbb', '0x4c'], # f       
        ]
        return inv_sbox
    def SUBSTITUTE_BYTES(self, block):
        for i in range(4):
            for j in range(4):
                val = hex(block[i][j])
                x = int(val[2], 16)
                y = int(val[3], 16)
                print(self.sbox[x][y], end=' ')
                block[i][j] = self.sbox[x][y] 
            print()
        return block
 

state1 = [[0x47, 0x40, 0xa3, 0x4c],
        [0x37, 0xd4, 0x70, 0x9f],
        [0x94, 0xe4, 0x3a, 0x42],
        [0xed, 0xa5, 0xa6, 0xbc]]


temp_instance = AES(1234567890123456, AES.ECB)
state1 = temp_instance.SUBSTITUTE_BYTES(state1)
for row in state1:
    print(row)



state1 = [0x47, 0x40, 0xa3, 0x4c,
          0x37, 0xd4, 0x70, 0x9f,
          0x94, 0xe4, 0x3a, 0x42,
          0xed, 0xa5, 0xa6, 0xbc]
key_XOR = [0xac, 0x19, 0x28, 0x57,
          0x77, 0xfa, 0xd1, 0x5c,
          0x66, 0xdc, 0x29, 0x00,
          0xf3, 0x21, 0x41, 0x6a]
rest = st.key_XOR(state1,key_XOR)
ct = 0
for i in range(4):
    for j in range(4):
        print(hex(rest[ct]), end = " ")
        ct+=1
    print()
'''