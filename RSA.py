import random
import math
import sys
import time

sys.setrecursionlimit(10000) #扩展递归深度

class RSA():
    def is_Prime(self, n): #Miller-Rabin素性检测,参数为n
        temp = n - 1 #n - 1
        if n <= 1:
            return False
        if n == 2 or n == 3:
            return True
        if (n % 2) == 0:
            return False
        s, r = temp, 0
        while (s % 2) == 0: #n-1转化为 s * 2^r
            s //= 2 
            r += 1
        for i in range(10):
            a = random.randint(2, n-1)
            b = self.large_power_mod(a, s, n)
            if b == 1 or b == temp:#费马小定理 初次检测
                continue
            for j in range(r): #二次探测 同个底数a检测r次
                b = self.large_power_mod(b, 2, n)
                if b == temp and j != (r-1):
                    break
                elif b == 1:
                    return False
            if b!= 1:
                return False
        return True

    def getGreatPrime(self, bits ):
        while True:
            p = random.getrandbits(bits)
            p |= (1 << bits - 1) | 1 #按位异或操作，使第1位与第2048位都为1
            if self.is_Prime(p):
                return p  

    def keySpawn(self, p, q):
        if p == q: #素数相同时，程序停止执行
            raise ValueError("所提供素数相同！")
        else:
            n = p * q
            ola = (p - 1) * (q - 1)
            public_key = [65537, n] #生成e，即公钥
            x, d, gcd = self.extended_gcd(ola, public_key[0]) #生成d，即公钥
            private_key = [d % ola , n]
        return public_key, private_key

    def extended_gcd(self, a, b):
        if b == 0:
            return 1, 0, a
        else:
            x, y, gcd = self.extended_gcd(b, a % b)
            x, y = y, (x- (a //b) * y)
            return x, y, gcd    
    
    def large_power_mod(self, base, exponent, modulus):
        result = 1
        base = base % modulus

        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent = exponent // 2
            base = (base * base) % modulus

        return result

    ###########↑生成公私钥  ↓加解密模块
    def encrypto(self, public_key, plaintext):
        encryped_text = self.large_power_mod(plaintext, public_key[0], public_key[1])
        encryped_text = hex(encryped_text)
        return encryped_text
    
    def decrypto(self, private_key, cryptedtext):
        decrypted_text = int(cryptedtext, 16)
        decrypted_text = self.large_power_mod(decrypted_text, private_key[0], private_key[1])
        return decrypted_text
    
    ###########↑加解密模块  ↓公共函数
    def read_file(self): 
        file_path = 'plain_text.txt'   #读取明文
        with open(file_path, 'r', encoding="utf-8") as file:
            ascii_plain = file.read()
        return ascii_plain
    
    def write_key(self, pub, pri):
        with open("key.txt", 'w') as file:
            file.write("Public key:[{},{}]\n".format(pub[0], pub[1]))
            file.write("Private key:[{},{}]\n".format(pri[0], pri[1]))

    def ascii_toBigNum(self, ascii_string): #将字符串转为为大数字，每个字节8bit合并
        char_plain = ascii_string.encode('utf-8')
        char_plain = int.from_bytes(char_plain, byteorder='little', signed = False)
        return char_plain
    
    def bigNum_toAscii(self,num):
        len1 = (num.bit_length() - 1) //8 + 1
        num = num.to_bytes(length = len1, byteorder = 'little', signed = False)
        ascii_plain = num.decode('utf-8')
        return ascii_plain

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

    def padding(self, text): #填充
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
    def left_rotate(self, x, n):
        x = x & 0xffffffff 
        return (x << n)| (x >> (32 - n)) #循环左移n位    
    
if __name__ == "__main__":
    rsa = RSA()
    plain_string = rsa.read_file()
    ####↑读取明文
    flag = eval(input("输入0进行明文加解密; 输入1进行数字签名与验证"))
    chose = eval(input("输入'0'使用随机密钥加解密；输入'1'使用外部密钥加解密"))
    if chose == 0:
        time1 = time.time()
        bit_length = int(eval(input("输入你想要的密钥位数")) / 2)
        prime1 = rsa.getGreatPrime(bit_length) #p 1024密钥能加密128字节
        prime2 = rsa.getGreatPrime(bit_length) #q
        public_Key, private_Key = rsa.keySpawn(prime1, prime2)
        print("公私密钥已生成,写入key.txt")
        rsa.write_key(public_Key, private_Key)
        time2 = time.time()
        print("密钥生成时间:{}s".format(time2 - time1))
    else:
        public_str = input("请输入公钥,以逗号区分")
        public_Key = public_str.split(sep=',')
        public_Key = [int(char) for char in public_Key]
        private_str = input("请输入私钥,以逗号区分")
        private_Key = private_str.split(sep=',')
        private_Key = [int(char) for char in private_Key]
    if flag == 0:
        plain_char = rsa.ascii_toBigNum(plain_string) #返回数字
        encrypted_char = rsa.encrypto(public_Key, plain_char)
        print("加密后密文为:",encrypted_char)
        decrypted_char = rsa.decrypto(private_Key, encrypted_char)
        decrypted_char = rsa.bigNum_toAscii(decrypted_char)
        print("解密后明文为:" ,decrypted_char)
    if flag == 1:
        md5 = MD5()
        bit_text = md5.padding(plain_string) #对消息m进行填充
        hash_text = md5.hash_solver(bit_text) #产生消息m的摘要
        hash_int = int.from_bytes(hash_text, byteorder='little', signed = False) #摘要从字节串转为大数
        encrypted_hash = rsa.encrypto(private_Key, hash_int) #对摘要进行私钥签名
        print("签名后摘要为:",encrypted_hash)
        decrypted_hash = rsa.decrypto(public_Key, encrypted_hash) #对签名进行公钥验签
        print("验签后摘要为:",hex(decrypted_hash))
        if decrypted_hash == hash_int:
            print("摘要与签名验签值相等, 验证签名成功！")
        
    input("输入<ENTER>结束程序")



