from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel, QGroupBox,QComboBox,QTextEdit
import concurrent.futures
import time
# S-DES 置换表和 S-Box
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]  # P10 置换表
P8 = [6, 3, 7, 4, 8, 5, 10, 9]  # P8 置换表
IP = [2, 6, 3, 1, 4, 8, 5, 7]  # 初始置换 IP
IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]  # 逆初始置换 IP^-1
EP = [4, 1, 2, 3, 2, 3, 4, 1]  # 扩展置换 EP
P4 = [2, 4, 3, 1]  # P4 置换表

SBox1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]  # SBox1
SBox2 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]  # SBox2

def generate_all_keys():
    return [[int(bit) for bit in format(i, '010b')] for i in range(1024)]

# 尝试用给定的密钥解密密文，如果解密结果与明文匹配，则返回该密钥
def try_key(key, plaintext, ciphertext):
    if decrypt(ciphertext, key) == plaintext:
        return key

# 使用所有可能的密钥尝试解密，返回所有成功的密钥及其对应的时间
def brute_force(plaintext, ciphertext):
    keys = generate_all_keys()
    successful_keys = []

    # 使用多线程来加速破解
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_key = {executor.submit(try_key, key, plaintext, ciphertext): key for key in keys}
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            if future.result() is not None:
                successful_keys.append((key, time.time()))

    return successful_keys

# 置换函数
def permute(input_bits, permutation_table):
    return [input_bits[i - 1] for i in permutation_table]

# 左移函数
def left_shift(bits, num_shifts):
    return bits[num_shifts:] + bits[:num_shifts]

# 异或操作
def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

# 密钥扩展函数，生成两个子密钥 k1 和 k2
def key_expansion(key):
    # P10 置换
    permuted_key = permute(key, P10)

    left, right = permuted_key[:5], permuted_key[5:]

    # 第一次左移
    left1 = left_shift(left, 1)
    right1 = left_shift(right, 1)
    k1 = permute(left1 + right1, P8)  # P8 置换生成 K1

    # 第二次左移
    left2 = left_shift(left1, 2)
    right2 = left_shift(right1, 2)
    k2 = permute(left2 + right2, P8)  # P8 置换生成 K2

    return k1, k2

# 轮函数 f_k
def f(R, k):
    # EP 置换
    permuted_R = permute(R, EP)

    # 与子密钥 k 进行异或
    xor_result = xor(permuted_R, k)

    # S-Box 输入
    left_sbox_input = xor_result[:4]
    right_sbox_input = xor_result[4:]

    # S-Box 替换
    row1 = (left_sbox_input[0] << 1) | left_sbox_input[3]  
    col1 = (left_sbox_input[1] << 1) | left_sbox_input[2]  
    sbox1_output = SBox1[row1][col1]

    row2 = (right_sbox_input[0] << 1) | right_sbox_input[3]  
    col2 = (right_sbox_input[1] << 1) | right_sbox_input[2]  
    sbox2_output = SBox2[row2][col2]

    # S-Box 输出转换为二进制
    sbox_output = [int(x) for x in f'{sbox1_output:02b}'] + [int(x) for x in f'{sbox2_output:02b}']

    # P4 置换
    return permute(sbox_output, P4)

# S-DES 加密函数
def encrypt(plaintext, key):
    k1, k2 = key_expansion(key)

    # 初始置换 IP
    IP_plaintext = permute(plaintext, IP)

    L0, R0 = IP_plaintext[:4], IP_plaintext[4:]

    # 第一轮 F 函数
    L1 = R0
    r0 = f(R0, k1)  
    R1 = xor(L0, r0) 

    # 交换左右
    L2 = R1
    r1 = f(L1, k2)  
    R2 = xor(L2, r1)  

    combined = R2 + L1  

    # 逆初始置换 IP_inv
    ciphertext = permute(combined, IP_inv)

    return ciphertext

def decrypt(ciphertext, key):
    k1, k2 = key_expansion(key)

    # 初始置换 IP
    IP_ciphertext = permute(ciphertext, IP)

    L0, R0 = IP_ciphertext[:4], IP_ciphertext[4:]

    # 第一轮 F 函数
    L1 = R0
    r0 = f(R0, k2)  
    R1 = xor(L0, r0) 

    # 交换左右
    L2 = R1
    r1 = f(L1, k1)  
    R2 = xor(L2, r1)

    combined = R2 + L1 

    # 逆初始置换 IP_inv
    plaintext = permute(combined, IP_inv)

    return plaintext

# 将字符转换为二进制数组 (8 位)
def char_to_bits(char):
    return [int(bit) for bit in f'{ord(char):08b}']

# 将二进制数组转换回字符
def bits_to_char(bits):
    return chr(int(''.join(map(str, bits)), 2))

# 将字符串转换为二进制数组
def string_to_bits(string):
    return [char_to_bits(char) for char in string]

# 将二进制数组转换回字符串
def bits_to_string(bits_list):
    return ''.join(bits_to_char(bits) for bits in bits_list)

# 加密字符串
def encrypt_string(plaintext_str, key):
    plaintext_bits = string_to_bits(plaintext_str)  # 将字符串转换为二进制
    ciphertext_bits_list = [encrypt(bits, key) for bits in plaintext_bits]  # 逐个加密
    return bits_to_string(ciphertext_bits_list)  # 将加密后的二进制结果转换回字符串

# 解密字符串
def decrypt_string(ciphertext_str, key):
    ciphertext_bits = string_to_bits(ciphertext_str)  # 将加密后的字符串转换为二进制
    decrypted_bits_list = [decrypt(bits, key) for bits in ciphertext_bits]  # 逐个解密
    return bits_to_string(decrypted_bits_list)  # 将解密后的二进制结果转换回字符串

class SDESEncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    

    def initUI(self):
        self.setWindowTitle('S-DES加解密程序')

        layout = QVBoxLayout()

        # 输入类型选择
        self.input_type_combo = QComboBox(self)
        self.input_type_combo.addItems(['二进制', 'ASCII字符串'])
        layout.addWidget(self.input_type_combo)
       # 破解组
        crack_group = QGroupBox('暴力破解')
        crack_layout = QVBoxLayout()

        self.crack_plaintext_input = QLineEdit(self)
        self.crack_plaintext_input.setPlaceholderText('输入明文')
        crack_layout.addWidget(self.crack_plaintext_input)

        self.crack_ciphertext_input = QLineEdit(self)
        self.crack_ciphertext_input.setPlaceholderText('输入密文')
        crack_layout.addWidget(self.crack_ciphertext_input)

        self.crack_result_label = QTextEdit(self)  # 将 QLabel 改为 QTextEdit
        self.crack_result_label.setReadOnly(True)  # 设置为只读，防止用户编辑
        crack_layout.addWidget(self.crack_result_label)

        self.crack_button = QPushButton('暴力破解', self)
        self.crack_button.clicked.connect(self.crack)
        crack_layout.addWidget(self.crack_button)

        crack_group.setLayout(crack_layout)
        layout.addWidget(crack_group)

        self.setLayout(layout)
        # 加密组
        encrypt_group = QGroupBox('加密')
        encrypt_layout = QVBoxLayout()
        self.encrypt_key_input = QLineEdit(self)
        self.encrypt_key_input.setPlaceholderText('输入10位密钥（仅0和1）')
        encrypt_layout.addWidget(self.encrypt_key_input)
        
        self.encrypt_plaintext_input = QLineEdit(self)
        self.encrypt_plaintext_input.setPlaceholderText('输入要加密的内容')
        encrypt_layout.addWidget(self.encrypt_plaintext_input)

        self.encrypt_result_label = QLabel('', self)
        encrypt_layout.addWidget(self.encrypt_result_label)

        self.encrypt_button = QPushButton('加密', self)
        self.encrypt_button.clicked.connect(self.encrypt)
        encrypt_layout.addWidget(self.encrypt_button)

        encrypt_group.setLayout(encrypt_layout)
        layout.addWidget(encrypt_group)

        # 解密组
        decrypt_group = QGroupBox('解密')
        decrypt_layout = QVBoxLayout()
        self.decrypt_key_input = QLineEdit(self)
        self.decrypt_key_input.setPlaceholderText('输入10位密钥（仅0和1）')
        decrypt_layout.addWidget(self.decrypt_key_input)
        
        self.decrypt_ciphertext_input = QLineEdit(self)
        self.decrypt_ciphertext_input.setPlaceholderText('输入要解密的内容')
        decrypt_layout.addWidget(self.decrypt_ciphertext_input)

        self.decrypt_result_label = QLabel('', self)
        decrypt_layout.addWidget(self.decrypt_result_label)

        self.decrypt_button = QPushButton('解密', self)
        self.decrypt_button.clicked.connect(self.decrypt)
        decrypt_layout.addWidget(self.decrypt_button)

        decrypt_group.setLayout(decrypt_layout)
        layout.addWidget(decrypt_group)

        self.setLayout(layout)
    def crack(self):
        try:
            plaintext = [int(bit) for bit in self.crack_plaintext_input.text()]
            if len(plaintext) != 8 or any(bit not in (0, 1) for bit in plaintext):
                raise ValueError("明文必须是8位，且为二进制数。")
            ciphertext = [int(bit) for bit in self.crack_ciphertext_input.text()]
            if len(ciphertext) != 8 or any(bit not in (0, 1) for bit in ciphertext):
                raise ValueError("密文必须是8位，且为二进制数。")

            start_time = time.time()
            keys = brute_force(plaintext, ciphertext)
            results = [(key, end_time - start_time) for key, end_time in keys]
            self.crack_result_label.clear()  # 清空文本框
            for key, time_spent in results:
                self.crack_result_label.append(f"找到密钥: {''.join(map(str, key))}，用时 {time_spent} 秒。")  # 使用 append 添加文本
        except Exception as e:
            self.crack_result_label.setText(f'错误: {str(e)}')

    def encrypt(self):
        try:
            key = [int(bit) for bit in self.encrypt_key_input.text()]
            if len(key) != 10 or any(bit not in (0, 1) for bit in key):
                raise ValueError("密钥必须是10位，且为二进制数。")
            if self.input_type_combo.currentText() == '二进制':
                plaintext = [int(bit) for bit in self.encrypt_plaintext_input.text()]
                if len(plaintext) != 8 or any(bit not in (0, 1) for bit in plaintext):
                    raise ValueError("明文必须是8位，且为二进制数。")
                ciphertext = encrypt(plaintext, key)
                self.encrypt_result_label.setText(f'密文: {"".join(map(str, ciphertext))}')
            else:  # 'ASCII字符串'
                plaintext_str = self.encrypt_plaintext_input.text()
                ciphertext_str = encrypt_string(plaintext_str, key)
                self.encrypt_result_label.setText(f'密文: {ciphertext_str}')
        except Exception as e:
            self.encrypt_result_label.setText(f'错误: {str(e)}')

    def decrypt(self):
        try:
            key = [int(bit) for bit in self.decrypt_key_input.text()]
            if len(key) != 10 or any(bit not in (0, 1) for bit in key):
                raise ValueError("密钥必须是10位，且为二进制数。")
            if self.input_type_combo.currentText() == '二进制':
                ciphertext = [int(bit) for bit in self.decrypt_ciphertext_input.text()]
                if len(ciphertext) != 8 or any(bit not in (0, 1) for bit in ciphertext):
                    raise ValueError("密文必须是8位，且为二进制数。")
                plaintext = decrypt(ciphertext, key)
                self.decrypt_result_label.setText(f'明文: {"".join(map(str, plaintext))}')
            else:  # 'ASCII字符串'
                ciphertext_str = self.decrypt_ciphertext_input.text()
                plaintext_str = decrypt_string(ciphertext_str, key)
                self.decrypt_result_label.setText(f'明文: {plaintext_str}')
        except Exception as e:
            self.decrypt_result_label.setText(f'错误: {str(e)}')

if __name__ == '__main__':
    app = QApplication([])
    ex = SDESEncryptionApp()
    ex.show()
    app.exec_()


