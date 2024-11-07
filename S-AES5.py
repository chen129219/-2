import random

# 定义S-AES算法的必要常量和辅助函数
S_BOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_S_BOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]
RCON1, RCON2 = 0x80, 0x30

# S-AES辅助函数
def sub_nibbles(state):
    return [S_BOX[nibble] for nibble in state]

def inv_sub_nibbles(state):
    return [INV_S_BOX[nibble] for nibble in state]

# 修改shift_rows和inv_shift_rows函数，使其适用于16位分组
def shift_rows(state):
    # 对于S-AES的16位分组，不需要实际的行移位
    return state

def inv_shift_rows(state):
    # 对于S-AES的16位分组，不需要实际的逆行移位
    return state

def add_key(state, key):
    return [s ^ k for s, k in zip(state, key)]

def key_expansion(key):
    w = [(key >> 8) & 0xFF, key & 0xFF]
    w.append(w[0] ^ RCON1 ^ ((S_BOX[w[1] >> 4] << 4) | S_BOX[w[1] & 0x0F]))
    w.append(w[2] ^ w[1])
    return [(w[i] >> 4, w[i] & 0x0F) for i in range(4)]

# 加密和解密函数
def encrypt(plaintext, key):
    state = [(plaintext >> 4) & 0xF, plaintext & 0xF]
    round_keys = key_expansion(key)
    state = add_key(state, round_keys[0])
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = add_key(state, round_keys[1])
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = add_key(state, round_keys[2])
    return (state[0] << 4) | state[1]

def decrypt(ciphertext, key):
    state = [(ciphertext >> 4) & 0xF, ciphertext & 0xF]
    round_keys = key_expansion(key)
    state = add_key(state, round_keys[2])
    state = inv_sub_nibbles(state)
    state = inv_shift_rows(state)
    state = add_key(state, round_keys[1])
    state = inv_sub_nibbles(state)
    state = inv_shift_rows(state)
    state = add_key(state, round_keys[0])
    return (state[0] << 4) | state[1]

# CBC模式加解密
def generate_iv():
    # 生成随机16位初始向量
    return random.randint(0, 0xFFFF)

def cbc_encrypt(plaintext, key, iv):
    ciphertext = []
    previous_block = iv
    for i in range(0, len(plaintext), 2):  # 每次处理2字节
        block = plaintext[i:i + 2]
        block = block[0] << 4 | block[1] if len(block) == 2 else block[0]
        block = block ^ previous_block  # XOR with previous ciphertext (or IV for first block)
        encrypted_block = encrypt(block, key)  # 使用S-AES加密
        ciphertext.append(encrypted_block)
        previous_block = encrypted_block  # 更新previous_block
    return ciphertext

def cbc_decrypt(ciphertext, key, iv):
    plaintext = []
    previous_block = iv
    for block in ciphertext:
        decrypted_block = decrypt(block, key)  # 使用S-AES解密
        decrypted_block ^= previous_block  # XOR with previous ciphertext (or IV for first block)
        plaintext.append(decrypted_block >> 4)  # 提取高4位
        plaintext.append(decrypted_block & 0xF)  # 提取低4位
        previous_block = block  # 更新previous_block
    return plaintext

# 篡改密文
def tamper_ciphertext(ciphertext):
    # 简单的篡改第一个密文块
    if len(ciphertext) > 0:
        ciphertext[0] ^= 0xFFFF  # 将第一个密文块进行XOR修改
    return ciphertext

# 测试
plaintext = [0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56]  # 一个明文消息（16位分组，拆分成字节）
key = 0x12345678  # 使用32位密钥
iv = generate_iv()  # 生成16位IV

# CBC加密
ciphertext = cbc_encrypt(plaintext, key, iv)
print(f"Original Ciphertext: {[hex(c) for c in ciphertext]}")

# 篡改密文
tampered_ciphertext = tamper_ciphertext(ciphertext)
print(f"Tampered Ciphertext: {[hex(c) for c in tampered_ciphertext]}")

# CBC解密
decrypted_plaintext = cbc_decrypt(ciphertext, key, iv)
print(f"Decrypted Plaintext (original): {decrypted_plaintext}")

# 解密篡改后的密文
decrypted_tampered_plaintext = cbc_decrypt(tampered_ciphertext, key, iv)
print(f"Decrypted Plaintext (tampered): {decrypted_tampered_plaintext}")
