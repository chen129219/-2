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

# 双重加密
def double_encrypt(plaintext, key):
    K1 = (key >> 16) & 0xFFFF
    K2 = key & 0xFFFF
    intermediate = encrypt(plaintext, K1)
    ciphertext = encrypt(intermediate, K2)
    return ciphertext

def double_decrypt(ciphertext, key):
    K1 = (key >> 16) & 0xFFFF
    K2 = key & 0xFFFF
    intermediate = decrypt(ciphertext, K2)
    plaintext = decrypt(intermediate, K1)
    return plaintext

# 三重加密
def triple_encrypt(plaintext, key, mode=1):
    if mode == 1:
        K1 = (key >> 16) & 0xFFFF
        K2 = key & 0xFFFF
        intermediate1 = encrypt(plaintext, K1)
        intermediate2 = decrypt(intermediate1, K2)
        ciphertext = encrypt(intermediate2, K1)
    elif mode == 2:
        K1 = (key >> 32) & 0xFFFF
        K2 = (key >> 16) & 0xFFFF
        K3 = key & 0xFFFF
        intermediate1 = encrypt(plaintext, K1)
        intermediate2 = decrypt(intermediate1, K2)
        ciphertext = encrypt(intermediate2, K3)
    return ciphertext

def triple_decrypt(ciphertext, key, mode=1):
    if mode == 1:
        K1 = (key >> 16) & 0xFFFF
        K2 = key & 0xFFFF
        intermediate1 = decrypt(ciphertext, K1)
        intermediate2 = encrypt(intermediate1, K2)
        plaintext = decrypt(intermediate2, K1)
    elif mode == 2:
        K1 = (key >> 32) & 0xFFFF
        K2 = (key >> 16) & 0xFFFF
        K3 = key & 0xFFFF
        intermediate1 = decrypt(ciphertext, K3)
        intermediate2 = encrypt(intermediate1, K2)
        plaintext = decrypt(intermediate2, K1)
    return plaintext

# 中间相遇攻击
def meet_in_the_middle_attack(known_plaintext, known_ciphertext):
    potential_keys = {}
    for K1 in range(0x10000):
        intermediate = encrypt(known_plaintext, K1)
        potential_keys[intermediate] = K1
    for K2 in range(0x10000):
        intermediate = decrypt(known_ciphertext, K2)
        if intermediate in potential_keys:
            K1 = potential_keys[intermediate]
            return (K1 << 16) | K2
    return None

# 示例测试
plaintext = 0xAB
double_key = 0x12345678
triple_key_mode1 = 0x12345678
triple_key_mode2 = 0x123456789ABC

# 双重加密测试
ciphertext_double = double_encrypt(plaintext, double_key)
decrypted_double = double_decrypt(ciphertext_double, double_key)
print(f"Double Encryption - Ciphertext: {hex(ciphertext_double)}, Decrypted: {hex(decrypted_double)}")

# 三重加密测试 (模式1和模式2)
ciphertext_triple_mode1 = triple_encrypt(plaintext, triple_key_mode1, mode=1)
decrypted_triple_mode1 = triple_decrypt(ciphertext_triple_mode1, triple_key_mode1, mode=1)
print(f"Triple Encryption Mode 1 - Ciphertext: {hex(ciphertext_triple_mode1)}, Decrypted: {hex(decrypted_triple_mode1)}")

ciphertext_triple_mode2 = triple_encrypt(plaintext, triple_key_mode2, mode=2)
decrypted_triple_mode2 = triple_decrypt(ciphertext_triple_mode2, triple_key_mode2, mode=2)
print(f"Triple Encryption Mode 2 - Ciphertext: {hex(ciphertext_triple_mode2)}, Decrypted: {hex(decrypted_triple_mode2)}")

# 中间相遇攻击测试
known_ciphertext = double_encrypt(plaintext, double_key)
found_key = meet_in_the_middle_attack(plaintext, known_ciphertext)
print(f"Meet-in-the-Middle Attack found key: {hex(found_key)}" if found_key else "Key not found")
