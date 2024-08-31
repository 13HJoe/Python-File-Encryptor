import random

class AES:
    ECB = 1
    CBC = 2
    def __init__(self, key, mode):
        self.mode = mode
        self.key =  key
        self.sbox = self.gen_SBOX()
        self.inv_sbox = self.gen_INVERSE_SBOX()


    
    def gen_SBOX(self):
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

    def get_hex_str_direct(self, i, j):
        dir = 'abcdef'
        res = '0x'
        if i >= 10:
            res += dir[10-i-1]
        else:
            res += str(i)
        if j >= 10:
            res += dir[10-j-1]
        else:
            res += str(j)
        return res

    def get_int(self, x):
        if x < 'a':
            return int(x)
        temp_dict = {'a' : 10,
                     'b' : 11,
                     'c' : 12,
                     'd' : 13,
                     'e' : 14,
                     'f' : 15,}
        return temp_dict[x]


    def gen_INVERSE_SBOX(self):
        inv_sbox = [[ hex(0)  for _ in range(16)] for _ in range(16)]
        for i in range(16):
            for j in range(16):
                val = str(self.sbox[i][j])
                x = self.get_int(val[2])
                y = self.get_int(val[3])
                #print(type(inv_sbox[i][j]))
                inv_sbox[x][y] = self.get_hex_str_direct(i,j)
        return inv_sbox

    def key_XOR(self, key_16, data_16):
        new_state = []
        for i in range(16):
            temp_res = key_16[i] ^ data_16[i]
            new_state.append(temp_res)
        return new_state
    
st = AES(123,AES.ECB)
for line in st.inv_sbox:
    print(line)


''''
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