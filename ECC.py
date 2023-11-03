import random

class ECC():
    def __init__(self,a, b, p):
        self.a = a
        self.b = b
        self.p = p
        self.origin =[0.1, 0.1] #定义无穷远点
        self.base_Point = [0, 0] #基点
        self.order = 0 #基点的阶
        self.k = random.randint(30,100) #解编码所用k

    def ecc_Points(self):
        points = list()
        for x in range(self.p): #计算方程右侧
            for y in range(self.p):
                if ((x ** 3 + self.a * x + self.b )% self.p) == ((y ** 2) % self.p):
                    points.append([x, y])
        return points
        
    def spawnKeys(self): # y^2 = x^3 + ax + b (mod p) 生成公私钥
        flag = eval(input("输入0不打印所有生成元; 输入1打印所有生成元： "))
        if flag == 1:
            points = self.ecc_Points()
            orders = list()
            for i in range(len(points)):
                orders.append(self.solve_order(points[i]))
                print("{}号生成元:{}   该生成元所对应的阶:{}".format(i, points[i], orders[i]))
            gen_num = eval(input("请输入你想选择的生成元的序号"))
            self.base_Point =  points[gen_num]
            self.order = orders[gen_num]
        else:
            flag_1 = eval(input("输入0使用椭圆曲线“secp256k1”的预设生成元; 输入1使用自定义生成元： "))
            if flag_1 == 0:
                self.base_Point[0] = eval("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
                self.base_Point[1] = eval("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
                self.order = eval("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
            if flag_1 == 1:
                self.base_Point[0] = eval(input("请输入生成元的x值: "))
                self.base_Point[1] = eval(input("请输入生成元的y值: "))
                flag_2 = eval(input("输入0自动计算生成元阶[慢]; 输入1手动输入生成元阶[快]： "))
                if flag_2 ==1:
                    self.order = eval(input("请输入生成元的阶n: "))
                if flag_2 ==0:
                    self.order = self.solve_order(self.base_Point)
        private_Key = eval(input("请输入你想选择的私钥(pri < {})".format(self.order)))
        public_Key = self.double_and_add(self.base_Point, private_Key)
        self.write_key(public_Key, private_Key)
        return private_Key, public_Key 
###↑密钥生成 ↓加解密模块
    def curve_Encode(self, m):
        char_point = []
        x = self.k * m
        for  j in range(self.k):
            f = self.large_power_mod((pow(x, 3) + self.a * x + self.b),1, self.p) #x^3 + ax + b (mod p)
            y = self.large_power_mod(f, (self.p + 1)//4, self.p) # y
            if (f == self.large_power_mod(y, 2, self.p)):
                char_point = [x, y]
                break
            x += 1
        print("编码后明文点: ", char_point) #输出pm
        return char_point
    
    def curve_Decode(self, Pm):
        m = Pm[0] // self.k
        return m
    
    def encrypyto(self, public_Key): #加密模块
        ascii_plain = self.read_file()
        ascii_num = self.ascii_toBigNum(ascii_plain) #将明文转为大数字
        char_point = self.curve_Encode(ascii_num) #编码函数
        encrypted_text = []
        r = random.randint(1, self.order-1)
        encrypted_x = self.double_and_add(self.base_Point, r) #rG
        encrypted_y = self.points_add(char_point, self.double_and_add(public_Key, r))
        encrypted_text = [encrypted_x,encrypted_y]
        return encrypted_text
    
    def decrypyto(self, encrypted_Text, private_Key):
        decrypted_Points = []
        decrypted_text = []
        decrypted_Points = (self.points_add(encrypted_Text[1], self.get_InversePoint(self.double_and_add(encrypted_Text[0], private_Key))))
        print("解密后明文点： ", decrypted_Points)
        decrypted_text = self.curve_Decode(decrypted_Points)
        decrypted_text = self.bigNum_toAscii(decrypted_text)
        return decrypted_text

###↑加解密模块 ↓公共函数+运算定义模块
    def extended_gcd(self, a, b): #扩展欧几里得 a为p，b为value 求值的逆元
        if b == 0:
            return 1, 0, a
        else:
            x, y, gcd = self.extended_gcd(b, a % b)
            x, y = y, (x- (a //b) * y)
            return x, y, gcd 
    
    def gcd(self,a, b): #求最大公因数
        if b == 0:
            return a
        else:
            return self.gcd(b, a % b)

    def get_InversePoint(self, point): #求P的逆元
        inverse = (-1 * point[1]) % self.p
        return [point[0], inverse]
    
    def points_add(self, point1, point2): #域上p+q加法
        x1,y1,x2,y2 = point1[0], point1[1] , point2[0] ,point2[1]
        flag = 1
        if point1 == self.origin:
            return point2
        if point2 == self.origin:
            return point1
        if self.get_InversePoint(point1) == point2:
            return self.origin
        if point1 != point2:
            lanta = [y2 - y1, x2 -x1] #lanta[分子, 分母]
        else: 
            lanta = [3 * (x1 ** 2) + self.a, 2 * y1]
        if lanta[0] * lanta[1] < 0:
            flag = 0
            lanta[0] = abs(lanta[0])
            lanta[1] = abs(lanta[1])
        gcd_num = self.gcd(lanta[0],lanta[1])
        lanta[0] //= gcd_num   
        lanta[1] //= gcd_num  
        j, inverse_value, l = self.extended_gcd(self.p ,lanta[1])
        inverse_value %= self.p
        k = lanta[0] * inverse_value
        if flag == 0:
            k = -k
        k %= self.p
        x3 = (k ** 2 -x1 -x2) % self.p
        y3 = (k *(x1 - x3) - y1) % self.p
        return [x3, y3]
    
    def double_and_add(self, point, n): #域上np算法
        # 将 n 转换为二进制表示
        binary_n = bin(n)[2:]
        temp = self.origin
        # 从最高位开始遍历 n 的二进制表示
        for bit in binary_n:
            # 点加倍操作
            temp = self.points_add(temp, temp)
            if bit == '1':
                # 点加法操作
                temp = self.points_add(temp, point)
        return temp
    
    def solve_order(self, point): #求某点的阶
        k = 2
        while True:
            temp = point[:]
            temp = self.double_and_add(temp, k)
            if(self.get_InversePoint(temp) ==point):
                return k + 1
            k += 1

    def large_power_mod(self, base, exponent, modulus): #快速模幂
        result = 1
        base = base % modulus

        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent = exponent // 2
            base = (base * base) % modulus

        return result
    
    def read_file(self): #读取明文
        file_path = 'plain_text.txt'  
        with open(file_path, 'r', encoding="utf-8") as file:
            ascii_plain = file.read()
        return ascii_plain
    
    def write_key(self, pub, pri): #存储钥匙
        with open("key.txt", 'w') as file:
            file.write("Public key:[{},{}]\n".format(pub[0], pub[1]))
            file.write("Private key:[{}]\n".format(pri))
    
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
    while True:
        print("椭圆曲线方程为y^2 = x^3+ax+b (mod p)")
        flag = eval(input("输入0则使用预设椭圆曲线“secp256k1” ; 输入1则使用自定义椭圆曲线： "))
        if flag == 0:
            a = eval("0")
            b = eval("7")
            p = eval(" 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
        else:
            a = eval(input("请输入椭圆曲线的a: "))
            b = eval(input("请输入椭圆曲线的b: "))
            p = eval(input("请输入椭圆曲线的p: "))
        if 4 * pow(a, 3) == -27 * pow(b, 2):
            print("4*a^3 + 27*b^2 == 0, 参数错误请重新输入")
        else: 
            break
    ecc = ECC(a, b, p)
    private_Key, public_Key = ecc.spawnKeys() #密钥生成
    print("私钥为： ", private_Key)
    print("公钥为： ", public_Key)
    encrypted_text = ecc.encrypyto(public_Key)
    print("加密后密文", encrypted_text)
    decrypted_text = ecc.decrypyto(encrypted_text, private_Key)
    print("解密后明文",decrypted_text)
    input("输入<ENTER>结束程序")
