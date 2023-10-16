#############AES-128########################
import numpy as np
import sys
import os

class AES:
    Sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]

    invSbox = [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D ]

    Rcon = [[0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00], [0x04, 0x00, 0x00, 0x00],[0x08, 0x00, 0x00, 0x00], [0x10, 0x00, 0x00, 0x00],
            [0x20, 0x00, 0x00, 0x00], [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00],[0x1B, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]]

    mixed_matrix = [[0x02, 0x03, 0x01, 0x01],
                    [0x01, 0x02, 0x03, 0x01],
                    [0x01, 0x01, 0x02, 0x03],
                    [0x03, 0x01, 0x01, 0x02]]

    inv_mixed_matrix = [[0x0e, 0x0b, 0x0d, 0x09],
                        [0x09, 0x0e, 0x0b, 0x0d],
                        [0x0d, 0x09, 0x0e, 0x0b],
                        [0x0b, 0x0d, 0x09, 0x0e]]

    def key_Expension(self, psw):
        psw_char = np.array(self.ascii_toChar(psw))
        psw_char = psw_char.reshape(4,4).T
        for i in range(4, 44):
            round = int(i / 4)
            temp0 = np.zeros((4,1))
            temp1 = np.zeros((4,1))  
            temp2 = np.zeros((4,1))
            temp1 = np.copy(psw_char[: , i-1])    #w[i-1]
            temp2 = np.copy(psw_char[: , i-4])    #w[i-4]
            if(i % 4 == 0): #i是4的倍数
                temp1 = self.func_T(temp1, round) #T(w[i-1])
            for i in range(len(temp1)):
                temp0[i] = int(temp1[i]) ^ int(temp2[i])
            psw_char = np.hstack((psw_char,temp0))
        return psw_char
        # print(psw_char)
                
    def func_T(self,array, round): # T函数
        #字循环
        temp = array[0]
        for i in range(3):
            array[i] = array[i+1]
        array[3] = temp
        #字节替换
        self.SubBytes_col(array)
        #轮常量异或
        self.Rcon_fun(array, round)
        return array

    def SubBytes_col(self, array): #字节替代(列)
        for i in range(4):
            column = array[i] % 16
            row = array[i] // 16
            array[i] = self.Sbox[int(16 * row  + column)]

    def SubBytes(self, array): #字节替代(4x4)
        for j in range(4):
            self.SubBytes_col(array[:,j])

    def Rcon_fun(self, array, round): #轮常量异或
        for i in range(4):
            array[i] = int(array[i]) ^ int(self.Rcon[round-1][i]) 

    def addRoundKey(self, array, key):
        for i in range(4):
            for j in range(4):
                array[i][j] = int(key[i][j]) ^ int(array[i][j])

    def shiftRows(self, array):
        for row in range(4):
            array[row] = np.roll(array[row], -row)
        
    def mixColumns(self, array):
        result = np.zeros((4,4))
        for i in range(4):
            for j in range(4):
                for k in range(4):
                    result[i][j] =self.GF_add(result[i][j] ,self.GF_mul(self.mixed_matrix[i][k], array[k][j]))
        return result 

    #↑encrypted ↓decrypted
    def rev_shiftRows(self, array):
        for row in range(4):
            array[row] = np.roll(array[row], row)

    def rev_subBytes(self, array):
        for j in range(4):
            for i in range(4):
                column = array[i,j] % 16
                row = array[i,j] // 16
                array[i,j] = self.invSbox[int(16 * row  + column)]

    def rev_mixColumns(self, array):
        result = np.zeros((4,4))
        for i in range(4):
            for j in range(4):
                for k in range(4):
                    result[i][j] =self.GF_add(result[i][j] ,self.GF_mul(self.inv_mixed_matrix[i][k], array[k][j]))
        return result 
    #↑decrypted ↓ global function

    def GF_add(self, num1, num2): #域上模2加
        return int(num1) ^ int(num2)

    def GF_mul(self, num1, num2): #域上模2乘
        num2 = int(num2)
        num1 = int(num1)
        irreducible_poly = 0b100011011
        result = 0
        # 逐位计算乘法
        for i in range(8):
            # 如果b的最低位是1，则将a加到结果中
            if num2 & 1:
                result ^= num1
            # 判断a的最高位是否为1
            if num1 & 0x80:
                # 左移一位并模2加上不可约多项式
                num1 = (num1 << 1) ^ irreducible_poly
            else:
                # 左移一位
                num1 <<= 1
            # 右移一位
            num2 >>= 1
        return result

    def ascii_toChar(self, ascii_string): 
        char_plain = [(ord(char)) for char in ascii_string] #将明文转化为char数组
        return char_plain

    def char_toAscii(self, char_string):
        ascii_string= ''.join([(chr(eval(char))) for char in char_string]) #将char数组转化回明文
        return ascii_string

    def char_toHex(self, char_string):
        vectorized_func = np.vectorize(self.decimal_to_hex)
        temp = np.copy(char_string)
        return (vectorized_func(temp.T.ravel()))

    def hex_toString(self, hex_array):
        int_array = np.array([int(x, 16) for x in hex_array])
        result = ''.join(chr(val) for val in int_array)
        return result

    # 定义将十进制数转换为十六进制的函数
    def decimal_to_hex(self, decimal):
        return hex(int(decimal))

    def encrypto(self, text): 
        self.addRoundKey(text, RoundKey[:,0:4]) #第一轮轮密钥加 w[0]-w[3]
        for i in range(1, 10):
            self.SubBytes(text) #字节替换
            self.shiftRows(text) #行移位
            text = self.mixColumns(text) #列混淆
            self.addRoundKey(text, RoundKey[:, 4 * i: 4*(i+1)]) #轮密钥加
        self.SubBytes(text)
        self.shiftRows(text)
        self.addRoundKey(text,RoundKey[:, 40:44]) #第十轮轮密钥加 w[40]-w[43]
        return text

    def decrypto(self, text):
        self.addRoundKey(text, RoundKey[:, 40:44]) #w[40]-w[43]
        for i in range(9, 0, -1):
            self.rev_shiftRows(text) #逆行移位
            self.rev_subBytes(text) #逆字节替换
            self.addRoundKey(text, RoundKey[:, 4 * i: 4*(i+1)]) #轮密钥加
            text = self.rev_mixColumns(text) #逆列混淆
        self.rev_shiftRows(text)
        self.rev_subBytes(text)
        self.addRoundKey(text, RoundKey[:,0:4]) # w[0]-w[3]    
        return text

#主函数
if __name__ == '__main__':
    file_path = 'plain_text.txt'   #读取明文
    with open(file_path, 'r') as file:
        ascii_plain = file.read()
    ascii_psw = input("请输入16字节长度密钥:")
    if (len(ascii_plain)!= 16 or len(ascii_psw)!=16):
        print("所输入明文或密钥并非16字节,请重新输入!")
        sys.exit
        
    aes = AES()
    char_plain = np.array(aes.ascii_toChar(ascii_plain))
    char_plain = char_plain.reshape((4,4)).T
    RoundKey = aes.key_Expension(ascii_psw) #密钥扩展 w[0]-w[43]
    char_plain = aes.encrypto(char_plain) #加密
    print("加密后的密文为：{}".format(aes.char_toHex(char_plain)))
    char_plain = aes.decrypto(char_plain) #解密12
    print("解密后的明文十六进制下为：{}".format(aes.char_toHex(char_plain)))
    string_plain = aes.hex_toString(aes.char_toHex(char_plain))
    print("解密后的明文为:{}".format(string_plain))
    input('Press <Enter> to exit')







