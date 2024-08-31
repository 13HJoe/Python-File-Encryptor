import random






class AES:
    ECB = 1
    CBC = 2
    def __init__(self, key, mode):
        self.mode = mode
        self.key =  key
        self.sbox = self.gen_SBOX()

    
    def gen_SBOX(self):
        sbox = []
        for _ in range(16):
            for _ in range(16):
                val = random.randrange(16, 256)
                sbox.append(hex(val))
        return sbox

    
    
    def key_XOR(self, key_16, data_16):
        new_state = []
        for i in range(16):
            temp_res = key_16[i] ^ data_16[i]
            new_state.append(temp_res)

        return new_state
    
st = AES(123,AES.ECB)
ct = 0 
for i in range(16):
    for j in range(16):
        print(st.sbox[ct], end = " ")
        ct+=1
    print()
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