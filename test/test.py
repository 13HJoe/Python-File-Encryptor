import random


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



'''
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