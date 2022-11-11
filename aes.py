import sys
import time

"""
Declaring global parameters required for AES: 
Round Constants
Sbox
Inverse Sbox
Mix Column Matrix
Inverse Mix Column Matrix
Initialization Vector: Used in CBC Mode
Number of Rounds 
Nk: Number of 32-bit Words in the Key/Number of Columns of Key Matrix
Expanded Keys
"""
rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

sbox = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a], 
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf], 
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]

inverse_sbox = [[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
                [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
                [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
                [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
                [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
                [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
                [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
                [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
                [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
                [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
                [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
                [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
                [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
                [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
                [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
                [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]]

mixColMatrix = [[2, 3, 1, 1],
                [1, 2, 3, 1],
                [1, 1, 2, 3],
                [3, 1, 1, 2]]

inv_mixColMatrix = [[14, 11, 13, 9],
                    [9, 14, 11, 13],
                    [13, 9, 14, 11],
                    [11, 13, 9, 14]]

IV = None
rounds = None
Nk = None
keys = None


def printMatrix(matrix):
    """
    PrettyPrint version for printing a matrix in Hex Format
    :param: matrix : list of lists
    """
    for i in matrix:
        for j in i:
            print(hex(j)[2:].upper().zfill(2), end = ' ')
        print()
        
    print()

def rowSubBytes(row, sbox):
    """
    Apply substitution to a row of matrix
    :param: row : row of the matrix
    :param: sbox : substitution table 
    """
    state = []
    for i in row:
        hexa = hex(i)[2:].zfill(2)
        row, col = int(hexa[0], 16), int(hexa[1], 16) 
        state.append(sbox[row][col])

    return state

def expandKey(key, rounds, Nk):
    """
    Expand the key 
    :param: key : key matrix
    :param: rounds : number of rounds 
    :param: Nk : number of 32-bit words/number of columns in the key matrix
    Refer to AES FIPS 197 for expansion algorithm
    """
    global sbox
    global keys
    keys = []

    for k in range(Nk):
        keys.append([key[i][k] for i in range(4)])

    for i in range(Nk, 4 * (rounds + 1)):
        word = keys[i - 1]
        if i % Nk == 0:
            word = word[1:] + word[:1]
            word = rowSubBytes(word, sbox)
            word[0] ^= rcon[i//Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            word = rowSubBytes(word, sbox)
        temp = keys[i - Nk]
        keys.append([temp[j] ^ word[j] for j in range(len(temp))])


def transposeMatrix(matrix):
    """
    Transpose a matrix 
    :param: matrix : a matrix
    """
    transposed_Mat = []
    for i in range(4):
        transposed_Mat.append([matrix[k][i] for k in range(len(matrix))])

    return transposed_Mat

def addRoundKey(matrix, key):
    """
    Xor Round key with the state Matrix
    :param: matrix : state matrix
    :param: key : round key matrix
    """
    state = []
    for i in range(len(matrix)):
        state_row = []
        for j in range(len(matrix)):
            state_row.append(matrix[i][j] ^ key[i][j])
        state.append(state_row)
        
    return state

def subBytes(matrix, sbox):
    """
    Apply substitution to state matrix
    :param: matrix : state matrix
    :param: sbox : substitution table 
    """
    state = []
    for i in matrix:
        state.append(rowSubBytes(i, sbox))
        
    return state

def shiftRow(matrix):
    """
    Shift rows to the left of the state matrix by 0, 1, 2, 3 corresponding to the row index
    :param: matrix : state matrix
    """
    state = []
    shift = 0
    for i in matrix:
        state.append(i[shift:] + i[:shift])
        shift += 1
    return state

def right_shiftRow(matrix):
    """
    Shift rows to the right of the state matrix by 0, 1, 2, 3 corresponding to the row index
    :param: matrix : state matrix
    """
    state = []
    shift = 0
    for i in matrix:
        state.append(i[-shift:] + i[:-shift])
        shift += 1
    return state

def galois_multiplication(numbers, multipliers):
    """
    Galois multiplication using Russian Peasant algorithm
    :param: numbers : a column of the state matrix
    :param: multipliers : corresponding row of the mix column matrix
    """
    irreducible = 0x1B
    result = 0
    for i in range(len(numbers)):
        a = numbers[i]
        b = multipliers[i]
        p = 0
        while(a != 0 and b != 0):
            if b & 1:
                p ^= a
            #Applying bitwise AND with 0xFF so that the number stays 8 bits
            b = (b >> 1) & 0xFF 
            if a > 127:
                a = ((a << 1) & 0xFF) ^ irreducible
            else:
                a = (a << 1) & 0xFF
        result ^= p

    return int(hex(result)[2:].zfill(2), 16)

def mixColumns(matrix, multiplier):
    """
    Applying mix column multiplication to state matrix
    :param: matrix : state matrix
    :param: multiplier : matrix to which state matrix will be multiplied
    """
    state = []
    total = len(matrix)
    for i in range(total):
        state_row = []
        for j in range(total):
            column = [matrix[k][j] for k in range(total)]
            state_row.append(galois_multiplication(column, multiplier[i]))
        state.append(state_row)
    return state

def readPlaintText(fileName):
    """
    Reading plain text from the file
    :param: fileName : file name in which plain text is stored
    :return: a 3D list in which 128-bit blocks of plaintext are stored in row major order 
    """
    with open(fileName) as f:
        lines = f.read().splitlines() 

    # Applying Padding
    for i in range(len(lines)):
        if (len(lines[i]) < 32):
            lines[i] = lines[i].ljust(32, '0')
            
    PT = []
    for i in range(len(lines)):
        subPT = []
        for j in range(0, 4):
            block = []
            for k in range(8 * j, 8 * (j + 1), 2):
                hexVal = lines[i][k:k + 2]
                block.append(int(hexVal, 16))
            subPT.append(block)
        PT.append(subPT)
    return PT

def readKey(fileName, mode = 128):
    """
    Reading key from the file 
    :param: fileName : file name in which key is stored
    :param: mode : AES mode 128/192/256
    :return: key matrix 
    """
    with open(fileName) as f:
        lines = f.read().splitlines()

    originalKey = lines[0]
    keySize = (mode // 32) 
    key = [[] for _ in range(keySize)]
    k = 0
    for i in range(keySize):
        for j in range(4):
            hexVal = originalKey[k:k + 2]
            key[i].append(int(hexVal, 16))
            k += 2

    return transposeMatrix(key)

def readIV(fileName):
    """
    Reading IV from the file 
    :param: fileName : file name in which IV is stored
    """
    global IV
    IV = []
    with open(fileName) as f:
        lines = f.read().splitlines()

    read_iv = lines[0]
    k = 0
    for i in range(0, 32, 8):
        subList = []
        for j in range(4):
            hexVal = read_iv[k : k + 2]
            subList.append(int(hexVal, 16))
            k += 2
        IV.append(subList)

    IV = transposeMatrix(IV)

def encryptBlock(PT, key):
    """
    Encrypting a 128-bit block 
    :param: PT : a 4x4 matrix of plain text
    :param: key : key matrix
    :return: encrypted matrix 
    """
    # Round 0
    state = addRoundKey(PT, key)

    # Rounds 1-n
    for i in range(1, rounds + 1):
        state = subBytes(state, sbox)
        state = shiftRow(state)
        if (i != rounds):    
            state = mixColumns(state, mixColMatrix)
        Key = keys[i * 4:  i * 4 + 4]
        roundKey = transposeMatrix(Key)
        state = addRoundKey(state, roundKey)
        
    return state

def decryptBlock(cipher, key):
    """
    Decrypting a 128-bit block of cipher text
    :param: cipher : a 4x4 matrix of cipher text
    :param: key : key matrix
    :return: decrypted matrix
    """
    state = cipher
    for i in range(rounds, 0, -1):
        Key = keys[i * 4:  i * 4 + 4]
        roundKey = transposeMatrix(Key)
        state = addRoundKey(state, roundKey)
        if (i != rounds):    
            state = mixColumns(state, inv_mixColMatrix)
        state = right_shiftRow(state) 
        state = subBytes(state, inverse_sbox)

    # Round 0
    state = addRoundKey(state, key)
    return state

def encrypt(plainText, key, ecborcbc):
    """
    Encrypt blocks of plain text and write the output to file
    :param: plainText : a 3D list containing 128 bit blocks of plain text
    :param: key : key matrix
    :param: ecborcbc : ECB or CBC mode    
    """
    print('Encryption')
    encrypted_cipher = []
    for i in range(len(plainText)):
        block = transposeMatrix(plainText[i])
        if ecborcbc == 'cbc':
            #Add initialization vector for block 0
            if i == 0:
                block = addRoundKey(block, IV)
            #Add previous cipher block for current block
            else:
                block = addRoundKey(block, encrypted_cipher[i - 1])
        encrypted_cipher.append(encryptBlock(block, key))
        printMatrix(encrypted_cipher[i])

    # Appending Cypher to a string to save to .enc file 
    cipherString = ""
    for i in range(len(encrypted_cipher)):
        block = transposeMatrix(encrypted_cipher[i])
        block = [hex(k)[2:].upper().zfill(2) for j in block for k in j]
        cipherString += ("".join(str(i) for i in block)) + '\n'

    # write to cipher.enc
    with open('encrypted.enc', 'w') as f:
        f.write(cipherString[:-1])


def decrypt(cipherText, key, ecborcbc):
    """
    Decrypt blocks of cipher text and write the output to file
    :param: cipherText : a 3D list containing 128 bit blocks of cipher text
    :param: key : key matrix
    :param: ecborcbc : ECB or CBC mode    
    """
    print('Decryption')
    decrypted_cipher = []
    for i in range(len(cipherText)):
        block = transposeMatrix(cipherText[i])
        block = decryptBlock(block, key)
        if ecborcbc == 'cbc':
            #Add initialization vector for block 0
            if i == 0:
                block = addRoundKey(block, IV)
            #Add previous cipher block for current block
            else:
                cipherBlock = transposeMatrix(cipherText[i - 1])
                block = addRoundKey(block, cipherBlock)
        decrypted_cipher.append(block)
        printMatrix(decrypted_cipher[i])

    # Appending Plaintext to a string to save to .dec file 
    plainText = ""
    for i in range(len(decrypted_cipher)):
        block = transposeMatrix(decrypted_cipher[i])
        block = [hex(k)[2:].upper().zfill(2) for j in block for k in j]
        plainText += ("".join(str(i) for i in block)) + '\n'

    # write to cipher.enc
    with open('decrypted.dec', 'w') as f:
        f.write(plainText[:-1])

def main():
    global rounds
    global Nk

    if (len(sys.argv) < 4):
        print("Not enough Cmd Arguments given.")
        return 0

    mode = int(sys.argv[1])
    encOrDec = sys.argv[2]
    ecbOrcbc = sys.argv[3]

    if (mode != 128 and mode != 192 and mode != 256):
        print("No mode given, exiting")
        return 0

    if (encOrDec.lower() != 'enc' and encOrDec.lower() != 'dec'):
        print("Not told whether to encrypt or decrypt, exiting")
        return 0

    if (ecbOrcbc.lower() != 'ecb' and ecbOrcbc.lower() != 'cbc'):
        print("Invalid Arguments")
        return 0
    
    if (mode == 128):
        rounds = 10
        Nk = 4
    elif (mode == 192):
        rounds = 12
        Nk = 6
    elif (mode == 256):
        rounds = 14
        Nk = 8
    else:
        print("Invalid mode, exiting.")
        return 0


    key = readKey("key.key", mode)
    readIV("IV.txt")
    expandKey(key, rounds, Nk)
    
    if (encOrDec == 'enc'):
        pt = readPlaintText("pt.pt")
        encrypt(pt, key, ecbOrcbc)
        
    else:
        cipher = readPlaintText("encrypted.enc")
        decrypt(cipher, key, ecbOrcbc)


if __name__ == '__main__':
    main()