import tkinter as tk
from tkinter import messagebox

# 简化的AES (S-AES) 参数
SBOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]  # S-盒
INVERSE_SBOX = [SBOX.index(x) for x in range(16)]  # 逆S-盒
RCON1 = 0x80  # 轮常量
RCON2 = 0x30  # 轮常量

def nibble_substitution(s):
    # 进行S-盒替换
    return [SBOX[b] for b in s]

def inverse_nibble_substitution(s):
    # 进行逆S-盒替换
    return [INVERSE_SBOX[b] for b in s]

def shift_row(s):
    # 行移位操作
    return [s[0], s[1], s[3], s[2]]

def inverse_shift_row(s):
    # 逆行移位操作
    return [s[0], s[1], s[3], s[2]]

def add_round_key(s, k):
    # 将状态和轮密钥按位异或
    return [si ^ ki for si, ki in zip(s, k)]

def key_expansion(key):
    # 密钥扩展函数
    w = [0] * 6
    w[0] = key >> 8
    w[1] = key & 0xFF
    w[2] = w[0] ^ RCON1 ^ (SBOX[w[1] >> 4] << 4 | SBOX[w[1] & 0xF])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ RCON2 ^ (SBOX[w[3] >> 4] << 4 | SBOX[w[3] & 0xF])
    w[5] = w[4] ^ w[3]
    return w

def state_from_int(n):
    # 将整数转为状态数组
    return [(n >> 12) & 0xF, (n >> 8) & 0xF, (n >> 4) & 0xF, n & 0xF]

def state_to_int(s):
    # 将状态数组转为整数
    return (s[0] << 12) | (s[1] << 8) | (s[2] << 4) | s[3]

def s_aes_decrypt(ciphertext, key):
    # S-AES 解密函数
    w = key_expansion(key)
    state = add_round_key(state_from_int(ciphertext), state_from_int((w[4] << 8) | w[5]))
    state = inverse_shift_row(state)
    state = inverse_nibble_substitution(state)
    state = add_round_key(state, state_from_int((w[2] << 8) | w[3]))
    state = inverse_shift_row(state)
    state = inverse_nibble_substitution(state)
    state = add_round_key(state, state_from_int((w[0] << 8) | w[1]))
    return state_to_int(state)

def decrypt():
    # 解密按钮的回调函数
    try:
        # 获取用户输入的密文和密钥
        ciphertext = int(ciphertext_entry.get(), 2)
        key = int(key_entry.get(), 2)
    except ValueError:
        # 显示错误信息
        messagebox.showerror("Error", "Both ciphertext and key must be 16-bit binary strings")
        return

    # 解密密文
    plaintext = s_aes_decrypt(ciphertext, key)
    # 显示解密后的明文
    plaintext_label.config(text="Plaintext: " + format(plaintext, '016b'))

# 设置主应用窗口
root = tk.Tk()
root.title("S-AES 解密器")

# 创建和放置控件
tk.Label(root, text="密文 (16-bit):").pack()
ciphertext_entry = tk.Entry(root)
ciphertext_entry.pack()

tk.Label(root, text="密钥 (16-bit):").pack()
key_entry = tk.Entry(root)
key_entry.pack()

decrypt_button = tk.Button(root, text="解密", command=decrypt)
decrypt_button.pack()

plaintext_label = tk.Label(root, text="明文:")
plaintext_label.pack()

# 启动GUI循环
root.mainloop()
