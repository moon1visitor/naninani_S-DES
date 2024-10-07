# naninani_S-DES
# S-DES
S-DES算法实现
## 一、项目简介
本项目是为学习S-DES算法而编写的Python代码，同时完成重庆大学2022级“信息安全导论”课程的作业。S-DES算法是一种对称密钥加密算法，其算法原理和实现过程与DES算法类似，但使用了不同的子密钥和置换表。该项目的核心功能包括数据的加密和解密，同时提供了一个图形用户界面（GUI），以便用户能够直观地与程序交互。通过图形用户界面，用户可以轻松地输入需要加密或解密的文本以及相应的密钥。程序会根据用户的输入执行相应的加密或解密操作，并在界面上展示结果。

## 二、S-DES程序结构

#### S-DES 相关参数
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

SBox1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
SBox2 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]

分组长度：明文和密文都以8位二进制数为单位处理。
密钥长度：初始密钥长度为10位二进制数。
#### 加密算法
初始置换（IP）：将输入的8-bit明文进行IP置换。
子密钥扩展：将10-bit初始密钥进行P10置换，并分为左右两半。
左移（Shift）：
第一轮左移1位。
第二轮左移2位。
扩展置换（EP）：对右半部分进行扩展置换。
S盒查找：对右半部分进行S盒查找，将6-bit输入映射到4-bit输出。
P盒置换：对S盒的输出进行P盒置换。
交换（SW）：交换左右两半。
第二轮处理：重复第一轮的扩展置换（EP）、S盒查找和P盒置换。
再次与左半部分进行异或操作。
最终置换（IP^{-1}）：对第二轮处理的结果进行最终置换，生成最终的8-bit密文。
#### 解密算法
初始置换（IP）：将输入的8-bit密文进行IP置换。
子密钥扩展：将10-bit初始密钥进行P10置换，并分为左右两半。
左移（Shift）：
第一轮左移1位。
第二轮左移2位。
扩展置换（EP）：对右半部分进行扩展置换。
S盒查找：对右半部分进行S盒查找，将6-bit输入映射到4-bit输出。
P盒置换：对S盒的输出进行P盒置换。
交换（SW）：交换左右两半。
第二轮处理：重复第一轮的扩展置换（EP）、S盒查找和P盒置换。
再次与左半部分进行异或操作。
最终置换（IP^{-1}）：对第二轮处理的结果进行最终置换，生成最终的8-bit明文。
#### 暴力破解
暴力破解是指通过尝试所有可能的密钥来解密已加密的消息。

暴力破解的实现方法是：  
1. 枚举所有可能的密钥。
2. 对于每个密钥，尝试解密密文。
3. 如果解密成功，则输出密钥。
4. 如果解密失败，则继续枚举下一个密钥。

## 三、实现功能

1. **多模式加解密**：支持ASCII模式和二进制模式下8-bit数据和10-bit密钥的加密和解密。
2. **跨平台一致性**：实现跨平台一致性，保证程序在不同平台上运行结果一致。
3. **扩展功能**：支持ASCII编码字符串的加密和解密。
4. **暴力破解**：支持暴力破解，通过尝试所有可能的密钥来解密已加密的消息。
5. **封闭测试**：判断是否存在多个密钥可以生成相同的密文。


## 四、代码实现
##### 生成密钥函数
generate_all_keys: 生成所有可能的10位二进制密钥，共1024种可能性。
try_key: 尝试用给定密钥解密，如果解密结果与明文匹配则返回该密钥。
brute_force: 使用多线程进行暴力破解，遍历所有密钥以找到匹配的结果。
```python
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
```
##### 加密与解密算法
encrypt: 实现S-DES的加密过程，分为多个步骤，包括密钥扩展、初始置换、轮函数操作和逆初始置换。
decrypt: 实现S-DES的解密过程，与加密过程相反，使用不同的子密钥顺序。
```python
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
```
##### 轮函数 f_k
这个函数实现了S-DES的轮函数操作。
```python
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

```

## 五、项目测试
#### 第1关：根据S-DES算法编写和调试程序，提供GUI解密支持用户交互。输入可以是8bit的数据和10bit的密钥，输出是8bit的密文
[![image](https://imgur.la/images/2024/10/07/image024da1b83d562ee1.md.png)](https://imgur.la/image/image.faCiF)
[![image](https://imgur.la/images/2024/10/07/image91e5dff336234c14.md.png)](https://imgur.la/image/image.faP5K)



经测试，该程序能够快速实现二进制模式下的加解密。




#### 第2关：交叉测试: 检测算法和程序是否可以在异构的系统或平台上都可以正常运行。


设有A和B两组位同学(选择相同的密钥K)；则A、B组同学编写的程序对明文P进行加密得到相同的密文C；或者B组同学接收到A组程序加密的密文C，使用B组程序进行解密可得到与A相同的P。


我们与其他组进行了交叉测试：


二进制加密选择相同的明文P为：01110100  选择相同的密钥K为：1011011001



二进制解密选择相同的密文P为：10000110  选择相同的密钥K为：1011011001




[![image](https://imgur.la/images/2024/10/07/image9117bc41222c38f4.md.png)](https://imgur.la/image/image.fDZ9b)
[![image](https://imgur.la/images/2024/10/07/imagee518d347c881bcbc.md.png)](https://imgur.la/image/image.fDeNN)
[![image](https://imgur.la/images/2024/10/07/image1bef2e6172e92b2c.md.png)](https://imgur.la/image/image.fDRnQ)



经检测，我们组结果与另外一组结果相同，通过交叉检测。







#### 第3关：扩展功能考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为1 Byte)，对应地输出也可以是ACII字符串(很可能是乱码)。
[![image](https://imgur.la/images/2024/10/07/imagee242818ec3eb4275.md.png)](https://imgur.la/image/image.fajnU)
[![image](https://imgur.la/images/2024/10/07/image1c259a7497412633.md.png)](https://imgur.la/image/image.faU5L)


经测试，该程序能够完成功能扩展，实现ASCII编码的加解密。




#### 第4关：暴力破解：检测是否能够实现暴力破解，且设置时间戳，记录暴力破解时间。
[![image](https://imgur.la/images/2024/10/07/imagec65e4bae8c2750af.md.png)](https://imgur.la/image/image.fDzKa)


经测试，该程序能够实现暴力破解

#### 第5关：封闭测试：分析是否存在多个密钥可以生成相同的密文
[![image](https://imgur.la/images/2024/10/07/imaged0e8a5f4ef8946fe.md.png)](https://imgur.la/image/image.fDCip)
[![image](https://imgur.la/images/2024/10/07/image5b2694d5b886f35f.md.png)](https://imgur.la/image/image.fD4A3)


经测试，该程序能够在较短时间内分析是否存在多个密钥可以生成相同的密文。

## 七、总结
本项目成功实现了S-DES加密算法，并提供了一个用户友好的图形用户界面（GUI），使得加密和解密过程更加直观和便捷。通过详细的算法描述和关键代码实现，项目满足了课程的基本要求，还通过多模式加解密、跨平台一致性测试、扩展功能实现、暴力破解和封闭测试等相关测试。
#### 项目待改进
性能优化：进一步优化算法实现，提高加解密的速度。



安全性增强：探索更多的安全性测试方法，增强算法的安全性。



用户界面改进：继续改进用户界面，使其更加现代化和用户友好。


## 八、开发团队
- 小组：风雨无组
- 团队成员： 柴钰林、古渲宇、陈芳莹
- 单位：重庆大学大数据与软件学院
