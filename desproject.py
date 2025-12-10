# des

class des:
    def __init__(self, hexkey): 
        self.bitkey = self.convert_hex(hexkey)          # convert the hex key to 64bits
        self.roundkeys = self.makesubkeys(self.bitkey)  # generate and store the 16 round keys from the 64bit key

    #helpers

    def convert_hex(self, hx):  # turn a hex string into a list of 64 bits
        v = int(hx, 16)                             # interpret the hex string as one big integer value
        return [(v >> (63 - i)) & 1 for i in range(64)]  # shift and mask to extract each bit from MSB to LSB

    def convertbits(self, bits):  # turn a list of bits back into a 16-character hex string
        v = 0                              # start from integer value 0
        for b in bits:                     # go through each bit in the list
            v = (v << 1) | b               # shift left by 1 and add the current bit at the least significant position
        return f"{v:016X}"                 # format the integer as 16 uppercase hex characters (64bit)

    def permute(self, bits, table):  # apply a permutation table to a list of bits
        return [bits[i - 1] for i in table]  # use each entry in the table (1-based index) to reorder/select bits

    def xor(self, a, b):  # perform bitwise XOR on two equal-length bit lists
        return [x ^ y for x, y in zip(a, b)]  # combine elements pairwise with XOR: 0^0=0, 0^1=1, 1^0=1, 1^1=0

    def leftshift(self, arr, n):  # perform circular left shift on a list by n positions
        return arr[n:] + arr[:n]  # cut off the first n elements and append them at the end

    #key schedule
    def makesubkeys(self, key64):  # generate 16 round keys from the original 64bit key
        k56 = self.permute(key64, pc1)      # apply PC1 to drop parity bits, turning 64bit into 56bit
        L, R = k56[:28], k56[28:]          # split the 56bit key into left half L and right half R (28 bits each)
        subkeys = []                       # list that will store each 48bit round key

        for s in shifttab:                             # for each round, use the corresponding left-shift value
            L = self.leftshift(L, s)                   # rotate the left half L by R bits
            R = self.leftshift(R, s)                   # rotate the right half R by s bits
            subkeys.append(self.permute(L + R, pc2))   # join L and R then apply PC2 to get 48bit round key

        return subkeys  # return list of 16 round keys (each 48 bits)

    #feistel
    def feistel(self, r, k):  #switches right to the left side pasted,the left side gets xored before going to the right side
        e = self.permute(r, expand)   # expand the 32bit right half to 48 bits using the expansion table
        x = self.xor(e, k)            # XOR expanded right half with the current round key
        out = []                      # will hold the 32bit result after S-box and P-box

        for i in range(8):                                                    # DES uses 8 S-boxes, each for 6 bits
            block = x[6*i : 6*i+6]                                           # take 6 bits for the current S-box
            row = (block[0] << 1) | block[5]                                 # row is formed from first and last bit
            col = (block[1]<<3) | (block[2]<<2) | (block[3]<<1) | block[4]   # column is formed from the middle 4 bits
            v = sbox[i][row][col]                                            # look up the 4bit output from the S-box
            out += [(v>>3)&1, (v>>2)&1, (v>>1)&1, v&1]                       # convert that 4bit value into 4 bits

        return self.permute(out, ptab)  # apply the P permutation to the 32bit output and return it

    #encrypt block
    def encrypt1(self, pt_hex):  # encrypt a single 64bit block given as 16-character hex string
        bits = self.convert_hex(pt_hex)         # convert plaintext hex block into list of 64 bits
        b = self.permute(bits, iptab)           # apply initial permutation to scramble bit positions
        l, r = b[:32], b[32:]                   # split into left half L0 and right half R0 (32 bits each)

        for k in self.roundkeys:                # run 16 Feistel rounds using the precomputed round keys in order
            l, r = r, self.xor(l, self.feistel(r, k))  # new L = old R, new R = old L XOR F(old R, round key)

        return self.convertbits(self.permute(r + l, fptab))  # after last round swap halves, apply final perm, back to hex

    #decrypt block
    def decrypt1(self, ct_hex):  # decrypt a single 64bit block given as 16-character hex string
        bits = self.convert_hex(ct_hex)         # convert ciphertext hex block into list of 64 bits
        b = self.permute(bits, iptab)           # apply the same initial permutation as encryption
        l, r = b[:32], b[32:]                   # split into left half L0 and right half R0

        for k in reversed(self.roundkeys):      # use round keys in reverse order for decryption
            l, r = r, self.xor(l, self.feistel(r, k))  # Feistel structure is symmetric, only key order changes

        return self.convertbits(self.permute(r + l, fptab))  # swap halves again, apply final permutation, back to hex


#MULTIb BLOCK ECB

def split_blocks(hexstring):  # split long hex string into 16-hex-character blocks (64bit)
    return [hexstring[i:i+16] for i in range(0, len(hexstring), 16)]

def encrypt_text(d, text):  # encrypt any length text using ECB, calling d.encrypt1 on each block
    hexdata = text_to_hex(text)              # convert text -> hex
    blocks = split_blocks(hexdata)           # split into 16-hex blocks

    # pad last block to 16 hex chars (if needed)
    if len(blocks[-1]) < 16:
        blocks[-1] = blocks[-1].ljust(16, "0")

    cipher_blocks = []                       # store encrypted blocks
    for b in blocks:
        cipher_blocks.append(d.encrypt1(b))  # encrypt each block with single-block DES

    return "".join(cipher_blocks)           # return full ciphertext as one long hex string

def decrypt_text(d, cipher_hex):  # decrypt any length ciphertext hex using ECB, calling d.decrypt1
    blocks = split_blocks(cipher_hex)       # split ciphertext into 16-hex blocks
    pt_hex = ""                             # this will store all plaintext hex

    for b in blocks:
        pt_hex += d.decrypt1(b)             # decrypt each 64bit block and append

    # remove padding zeros from the right (only the ones we added with ljust)
    return hex_to_text(pt_hex.rstrip("0"))  # convert hex back to text and return


#tables
iptab = [  # initial permutation table: reorders 64bit input before rounds
    58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
]

fptab = [  # final permutation table: inverse of IP, applied after the 16 rounds
    40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
]

expand = [  # expansion table: expands 32bit R to 48 bits by repeating some bits
    32,1,2,3,4,5,4,5,6,7,8,9,
    8,9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1
]

ptab = [  # P-box table: permutes the 32bit output from the S-boxes
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
]

pc1 = [  # PC1 table: selects 56 bits from 64bit key (drops parity bits)
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,21,13,5,28,20,12,4
]

pc2 = [  # PC2 table: selects 48 bits from 56bit (L,R) combined to form round key
    14,17,11,24,1,5,3,28,15,6,21,10,
    23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32
]

shifttab = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]  # how many bits to rotate L and R at each of the 16 rounds

sbox = [  # list of 8 S-boxes, each maps 6 input bits to 4 output bits
    # S1
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],   
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],   
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],   
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]    
    ],

    # S2
    [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],   
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],   
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],   
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]   
    ],

    # S3
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],   
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],   
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],   
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]    
    ],

    # S4
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],   
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],   
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],   
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]   
    ],

    # S5
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],   
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],  
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],   
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]   
    ],

    # S6
    [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],  
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],   
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],  
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]    
    ],

    # S7
    [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],  
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],   
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],  
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]   
    ],

    # S8
    [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],  
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],   
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],   
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]   
    ]
]

#menu functions
def text_to_hex(text):  # convert a normal text string into hex representation (2 hex chars per character)
    return ''.join(f"{ord(c):02X}" for c in text)  # for each character, get its ASCII code and format as 2-digit hex

def hex_to_text(hx):  # convert a hex string back into a normal text string
    out = []                                             # list to collect decoded characters
    for i in range(0, len(hx), 2):                       # process 2 hex digits at a time
        out.append(chr(int(hx[i:i+2], 16)))              # convert the 2 hex digits to int then to the corresponding char
    return ''.join(out)                                  # join list into a single string and return it

def pad_hex(hx):  # (kept in case you still want single-block testing) ensure exactly 16 hex chars
    return hx.ljust(16, '0')[:16]

def main():  #menu to choose encrypt or decrypt
    print("1) encrypt word (any length)")         
    print("2) decrypt hex (any length)")           
    ch = input("choose: ")                         

    key = input("enter 16 hex digit key: ").strip()     
    if len(key) != 16:                                   # DES key here must be exactly 16 hex chars
        print("invalid key length (must be 16 hex digits)")
        return

    d = des(key)                                         # create DES object with that key

    if ch == "1":                                        
        text = input("word: ")                           # ask the user for plaintext
        cipher = encrypt_text(d, text)                  
        print("cipher hex:", cipher)

    elif ch == "2":                                      
        hx = input("full hex ciphertext: ")              # ask for full ciphertext hex
        plain = decrypt_text(d, hx)                      # decrypt whole thing
        print("word:", plain)

#program entry 
if __name__ == "__main__":                                      # if file is correct it will work
    # test to check if its working
    print("running des self-test...")                          
    tester = des("133457799BBCDFF1")                           
    result = tester.encrypt1("0123456789ABCDEF")               
    print("test cipher :", result)                             
    print("expected    : 85E813540F0AB405")                   
    print("self-test ok (if they match)\n")                    

    # run menu
    main()                                                     
