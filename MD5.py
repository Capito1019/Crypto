import math

class MD5():
    def __init__(self):
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476
        # 定义MD5算法中的循环函数
        self.F = lambda x, y, z: (x & y) | (~x & z)
        self.G = lambda x, y, z: (x & z) | (y & ~z)
        self.H = lambda x, y, z: x ^ y ^ z
        self.I = lambda x, y, z: y ^ (x | ~z)
        self.k =  [math.floor(abs(math.sin(k+1)) * pow(2,32)) for k in range(64)] #常量k[i]

    shift_r = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
               5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
               4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
               6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    def padding(self): #填充
        text = self.read_file()
        bit_Text = bytearray(text.encode('utf-8'))
        text_length = (8 * len(bit_Text)) & 0xffffffffffffffff
        bit_Text.append(0x80)
        while len(bit_Text) % 64 != 56:
            bit_Text.append(0x00)
        bit_Text += text_length.to_bytes(8, 'little')
        return bit_Text

    def hash_solver(self, bit_Text):
        for i in range(0, len(bit_Text), 64): #每64字节为一块chunk进行散列
            chunk = bit_Text[i: i + 64] #每4字节为一个子分组，共16个子分组 w[k] = chunk[4k, 4k+3]
            a,b,c,d = self.A, self.B, self.C, self.D #初始化缓冲区
            for j in range(64): #每轮执行16次，4轮分别用F、G、H、I函数
                if j < 16:
                    f = self.F(b, c, d)
                    g = j
                if 16 <= j < 32:
                    f = self.G(b, c, d)
                    g = (5 * j + 1) % 16
                if 32 <= j < 48:
                    f = self.H(b, c, d)
                    g = (3 * j + 5) % 16
                if 48<= j < 64:
                    f = self.I(b, c, d)
                    g = (7 * j) % 16
                d_temp = d
                d = c
                c = b
                b = (b + self.left_rotate((a + f + self.k[j] + int.from_bytes(chunk[4 * g:4 * g + 4], 'little')), self.shift_r[j]))  & 0xffffffff
                a = d_temp
            self.A = (self.A + a) & 0xFFFFFFFF
            self.B = (self.B + b) & 0xFFFFFFFF
            self.C = (self.C + c) & 0xFFFFFFFF
            self.D = (self.D + d) & 0xFFFFFFFF
        return self.A.to_bytes(4, 'little') + self.B.to_bytes(4, 'little') + self.C.to_bytes(4, 'little') + self.D.to_bytes(4, 'little')
    ###散列函数↑ 公共函数↓
    def read_file(self): #读取明文
        file_path = 'plain_text.txt'  
        with open(file_path, 'r', encoding="utf-8") as file:
            ascii_plain = file.read()
        return ascii_plain
    
    def left_rotate(self, x, n):
        x = x & 0xffffffff 
        return (x << n)| (x >> (32 - n)) #循环左移n位
    
if __name__ == "__main__":
    md5 = MD5()
    bit_Text = md5.padding()
    hash_Text = md5.hash_solver(bit_Text)
    flag = eval(input("输入0摘要以十六进制输出; 输入1摘要以字节输出: "))
    print(hash_Text)
    if flag == 0:
        print(hash_Text.hex())
    elif flag == 1:
        print(hash_Text)
    input("输入<ENTER>离开程序")