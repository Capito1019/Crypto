import random
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
    
if __name__ == "__main__":
    rsa = RSA()
    plain_string = rsa.read_file()
    plain_char = rsa.ascii_toBigNum(plain_string) #返回字符串长度与数字
    ####↑读取明文
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
    encrypted_char = rsa.encrypto(public_Key, plain_char)
    print("加密后密文为:",encrypted_char)
    decrypted_char = rsa.decrypto(private_Key, encrypted_char)
    decrypted_char = rsa.bigNum_toAscii(decrypted_char)
    print("解密后明文为:" ,decrypted_char)
    input("输入<ENTER>结束程序")



